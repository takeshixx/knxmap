import asyncio
import codecs
import collections
import functools
import logging
import socket
import struct
import time

try:
    # Python 3.4
    from asyncio import JoinableQueue as Queue
except ImportError:
    # Python 3.5 renamed it to Queue
    from asyncio import Queue

import knxmap.utils
from knxmap.data.constants import *
from knxmap.messages import CemiFrame, KnxDescriptionResponse, KnxEmi1Frame
from knxmap.gateway import *
from knxmap.targets import *
from knxmap.exceptions import *
from knxmap.bus.tunnel import KnxTunnelConnection
from knxmap.bus.router import KnxRoutingConnection
from knxmap.bus.monitor import KnxBusMonitor

LOGGER = logging.getLogger(__name__)

try:
    import hid
    USB_SUPPORT = True
except ImportError:
    USB_SUPPORT = False


class KnxMap(object):
    """The main scanner instance that takes care of scheduling
    workers for the targets."""
    def __init__(self, targets=None, max_workers=100, max_connections=1,
                 loop=None, medium='net', configuration_reads=True,
                 bus_timeout=2, iface=False, auth_key=0xffffffff,
                 testing=False, ignore_auth=False, nat_mode=False):
        self.loop = loop or asyncio.get_event_loop()
        # The number of concurrent workers
        # for discovering KNXnet/IP gateways
        self.max_workers = max_workers
        # The number of concurrent tunnel connection
        # (0 means use as much as a device supports)
        self.max_connections = max_connections
        # q contains all KNXnet/IP gateways
        self.q = Queue(loop=self.loop)
        # bus_queues is a dict containing a bus queue for each KNXnet/IP gateway
        self.bus_queues = {}
        # bus_protocols is a list of all bus protocol instances for proper connection shutdown
        self.bus_protocols = []
        # knx_gateways is a list of KnxTargetReport objects, one for each found KNXnet/IP gateway
        self.knx_gateways = []
        # bus_devices is a list of KnxBusTargetReport objects, one for each found bus device
        self.bus_devices = set()
        self.bus_info = False
        self.t0 = time.time()
        self.t1 = None
        self.iface = None
        self.desc_timeout = None
        self.desc_retries = None
        self.knx_source = None
        self.medium = medium
        self.bus_connections = collections.OrderedDict()
        self.configuration_reads = configuration_reads
        self.bus_timeout = bus_timeout
        self.auth_key = auth_key
        self.iface = iface
        self.testing = testing
        self.ignore_auth = ignore_auth
        self.nat_mode = nat_mode
        if targets:
            self.set_targets(targets)
        else:
            self.targets = set()

    def set_targets(self, targets):
        self.targets = targets
        for target in self.targets:
            self.add_target(target)

    def add_target(self, target):
        self.q.put_nowait(target)

    def add_bus_queue(self, gateway, bus_targets):
        self.bus_queues[gateway] = Queue(loop=self.loop)
        for target in bus_targets:
            self.bus_queues[gateway].put_nowait(target)
        return self.bus_queues[gateway]

    @asyncio.coroutine
    def bruteforce_auth_key(self, knx_gateway, target, full_key_space=False, wordlist=None):
        if isinstance(target, set):
            target = list(target)[0]
        future = asyncio.Future()
        transport, protocol = yield from self.loop.create_datagram_endpoint(
            functools.partial(KnxTunnelConnection, future, nat_mode=self.nat_mode),
            remote_addr=(knx_gateway[0], knx_gateway[1]))
        self.bus_protocols.append(protocol)
        # Make sure the tunnel has been established
        connected = yield from future
        alive = yield from protocol.tpci_connect(target)
        if wordlist: 
            key_space = []
            with open(wordlist, 'r') as f:
                for line in f.readlines():
                    line = line.rstrip()                   
                    try: 
                        key_space.append(int('0x' + line, 0))
                    except ValueError: 
                        LOGGER.error('Key {} is not a valid hex value'.format(line))                
        elif full_key_space:
            key_space = range(0, 0xffffffff)
        else:            
            key_space = [0x11223344, 0x12345678, 0x00000000, 0x87654321, 0x11111111, 0xffffffff]

        # Bruteforce the key via A_Authorize_Request messages
        for key in key_space:
            access_level = yield from protocol.apci_authenticate(target, key)
            if access_level == 0:
                LOGGER.info("GOT THE KEY: {}".format(format(key, '08x')))
                break

    @asyncio.coroutine
    def _knx_description_worker(self):
        """Send a KnxDescription request to see if target is a KNX device."""
        try:
            while True:
                target = self.q.get_nowait()
                LOGGER.debug('Scanning {}'.format(target))
                response = None
                for _try in range(self.desc_retries):
                    LOGGER.debug('Sending {}. KnxDescriptionRequest to {}'.format(_try, target))
                    future = asyncio.Future()
                    yield from self.loop.create_datagram_endpoint(
                        functools.partial(KnxGatewayDescription, future,
                                          timeout=self.desc_timeout, nat_mode=self.nat_mode),
                        remote_addr=target)
                    response = yield from future
                    if response:
                        break

                if response and isinstance(response, KnxDescriptionResponse):
                    target_report = KnxTargetReport(
                        host=target[0],
                        port=target[1],
                        mac_address=response.dib_dev_info.get('knx_mac_address'),
                        knx_address=response.dib_dev_info.get('knx_address'),
                        device_serial=response.dib_dev_info.get('knx_device_serial'),
                        friendly_name=response.dib_dev_info.get('device_friendly_name'),
                        device_status=response.dib_dev_info.get('device_status'),
                        knx_medium=response.dib_dev_info.get('knx_medium'),
                        project_install_identifier=response.dib_dev_info.get('project_install_identifier'),
                        supported_services=[
                            KNX_SERVICES[k] for k, v in
                            response.dib_supp_sv_families.get('families').items()],
                        bus_devices=[])

                    # TODO: should we check if the device announces support? (support is mandatory)
                    if self.configuration_reads:
                        # Try to create a DEVICE_MGMT_CONNECTION connection
                        future = asyncio.Future()
                        transport, bus_protocol = yield from self.loop.create_datagram_endpoint(
                            functools.partial(
                                KnxTunnelConnection,
                                future,
                                connection_type=_CONNECTION_TYPES.get('DEVICE_MGMT_CONNECTION'),
                                ndp_defer_time=self.bus_timeout,
                                knx_source=self.knx_source,
                                nat_mode=self.nat_mode),
                            remote_addr=target)
                        self.bus_protocols.append(bus_protocol)
                        # Make sure the tunnel has been established
                        connected = yield from future
                        if connected:
                            configuration = collections.OrderedDict()
                            # Read additional individual addresses
                            count = yield from bus_protocol.configuration_request(
                                        target,
                                        object_type=11,
                                        start_index=0,
                                        property=OBJECTS.get(11).get('PID_ADDITIONAL_INDIVIDUAL_ADDRESSES'))
                            if count and count.data:
                                count = int.from_bytes(count.data, 'big')
                                conf_response = yield from bus_protocol.configuration_request(
                                        target,
                                        object_type=11,
                                        num_elements=count,
                                        property=OBJECTS.get(11).get('PID_ADDITIONAL_INDIVIDUAL_ADDRESSES'))
                                if conf_response and conf_response.data:
                                    data = conf_response.data
                                    target_report.additional_individual_addresses = []
                                    for addr in [data[i:i+2] for i in range(0, len(data), 2)]:
                                        target_report.additional_individual_addresses.append(
                                            knxmap.utils.parse_knx_address(int.from_bytes(addr, 'big')))

                            # Read manufacurer ID
                            count = yield from bus_protocol.configuration_request(
                                        target,
                                        object_type=0,
                                        start_index=0,
                                        property=OBJECTS.get(0).get('PID_MANUFACTURER_ID'))
                            if count and count.data:
                                count = int.from_bytes(count.data, 'big')
                                conf_response = yield from bus_protocol.configuration_request(
                                        target,
                                        object_type=0,
                                        num_elements=count,
                                        property=OBJECTS.get(0).get('PID_MANUFACTURER_ID'))
                                if conf_response and conf_response.data:
                                    target_report.manufacturer = knxmap.utils.get_manufacturer_by_id(
                                        int.from_bytes(conf_response.data, 'big'))

                            # TODO: do more precise checks what to extract and add it to the target report
                            # for k, v in OBJECTS.get(11).items():
                            #     count = yield from bus_protocol.configuration_request(target,
                            #                                                           object_type=11,
                            #                                                           start_index=0,
                            #                                                           property=v)
                            #     if count and count.data:
                            #         count = int.from_bytes(count.data, 'big')
                            #     else:
                            #         continue
                            #     conf_response = yield from bus_protocol.configuration_request(target,
                            #                                                                   object_type=11,
                            #                                                                   num_elements=count,
                            #                                                                   property=v)
                            #     if conf_response and conf_response.data:
                            #
                            #         print(k + ':')
                            #         print(conf_response.data)

                            bus_protocol.knx_tunnel_disconnect()

                    # TODO: at the end, add alive gateways to this list
                    self.knx_gateways.append(target_report)
                self.q.task_done()
        except (asyncio.CancelledError, asyncio.QueueEmpty):
            pass

    @asyncio.coroutine
    def monitor(self, targets=None, group_monitor_mode=False):
        if targets:
            self.set_targets(targets)
        if group_monitor_mode:
            LOGGER.debug('Starting group monitor')
        else:
            LOGGER.debug('Starting bus monitor')
        future = asyncio.Future()
        transport, protocol = yield from self.loop.create_datagram_endpoint(
            functools.partial(KnxBusMonitor, future, group_monitor=group_monitor_mode),
            remote_addr=list(self.targets)[0])
        self.bus_protocols.append(protocol)
        yield from future
        if group_monitor_mode:
            LOGGER.debug('Starting group monitor')
        else:
            LOGGER.debug('Starting bus monitor')

    @asyncio.coroutine
    def _knx_search_worker(self):
        """Send a KnxSearch request to see if target is a KNX device."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            struct.pack('256s', str.encode(self.iface)))
            protocol = KnxGatewaySearch(multicast_addr=self.multicast_addr,
                                        port=self.port)
            waiter = asyncio.Future(loop=self.loop)
            transport = self.loop._make_datagram_transport(
                sock, protocol, (self.multicast_addr, self.port), waiter)
            try:
                # Wait until connection_made() has been called on the transport
                yield from waiter
            except asyncio.CancelledError:
                LOGGER.error('Creating multicast transport failed!')
                transport.close()
                return

            # Wait SEARCH_TIMEOUT seconds for responses to our multicast packets
            yield from asyncio.sleep(self.search_timeout)

            if protocol.responses:
                if True:
                    # TODO: check if we want diagnostic requests as well
                    print('sending diagnostic request')
                    protocol.send_diagnostic_request()
                    yield from asyncio.sleep(self.search_timeout)

                # If protocol received SEARCH_RESPONSE packets, print them
                for response in protocol.responses:
                    peer = response[0]
                    response = response[1]
                    t = KnxTargetReport(
                        host=peer[0],
                        port=peer[1],
                        mac_address=response.dib_dev_info.get('knx_mac_address'),
                        knx_address=response.dib_dev_info.get('knx_address'),
                        device_serial=response.dib_dev_info.get('knx_device_serial'),
                        friendly_name=response.dib_dev_info.get('device_friendly_name'),
                        device_status=response.dib_dev_info.get('device_status'),
                        knx_medium=response.dib_dev_info.get('knx_medium'),
                        project_install_identifier=response.dib_dev_info.get('project_install_identifier'),
                        supported_services=[
                            KNX_SERVICES[k] for k, v in
                            response.dib_supp_sv_families.get('families').items()],
                        bus_devices=[])

                    self.knx_gateways.append(t)
        except asyncio.CancelledError:
            pass

    @asyncio.coroutine
    def _search_gateways(self):
        self.t0 = time.time()
        yield from asyncio.ensure_future(asyncio.Task(self._knx_search_worker(), loop=self.loop))
        self.t1 = time.time()
        LOGGER.info('Scan took {} seconds'.format(self.t1 - self.t0))

    @asyncio.coroutine
    def search(self, search_timeout=5, iface=None, multicast_addr='224.0.23.12',
               port=3671):
        self.iface = iface
        self.multicast_addr = multicast_addr
        self.port = port
        self.search_timeout = search_timeout
        LOGGER.info('Make sure there are no filtering rules that drop UDP multicast packets!')
        yield from self._search_gateways()
        if not self.testing:
            for t in self.knx_gateways:
                print_knx_target(t)
        LOGGER.info('Searching done')

    @asyncio.coroutine
    def brute(self, targets=None, bus_target=None, full_key_space=False, wordlist=None):
        if targets:
            self.set_targets(targets)
        tasks = [asyncio.Task(self.bruteforce_auth_key(t, bus_target, full_key_space, wordlist),
                              loop=self.loop) for t in self.targets]
        yield from asyncio.wait(tasks)

    @asyncio.coroutine
    def _knx_bus_worker(self, transport, protocol, knx_gateway=None, queue=None):
        """A worker for communicating with devices on the bus."""
        if not queue and not knx_gateway:
            LOGGER.error('No target queue available')
            return
        elif not queue and knx_gateway:
            queue = self.bus_queues.get(knx_gateway.host)
        try:
            while True:
                target = queue.get_nowait()
                LOGGER.info('BUS: target: {}'.format(target))
                if not protocol.tunnel_established:
                    LOGGER.error('KNX tunnel is not open!')
                    return

                alive = yield from protocol.tpci_connect(target)

                if alive:
                    properties = collections.OrderedDict()
                    serial = None

                    # DeviceDescriptorRead
                    descriptor = yield from protocol.apci_device_descriptor_read(target)
                    if not descriptor:
                        tunnel_request = protocol.make_tunnel_request(target)
                        tunnel_request.tpci_unnumbered_control_data('DISCONNECT')
                        protocol.send_data(tunnel_request.get_message(), target)
                        queue.task_done()
                        continue

                    if not self.bus_info:
                        t = KnxBusTargetReport(address=target)
                        self.bus_devices.add(t)
                        tunnel_request = protocol.make_tunnel_request(target)
                        tunnel_request.tpci_unnumbered_control_data('DISCONNECT')
                        protocol.send_data(tunnel_request.get_message(), target)
                        queue.task_done()
                        continue

                    dev_desc = struct.unpack('!H', descriptor)[0]
                    desc_medium, desc_type, desc_version = knxmap.utils.parse_device_descriptor(dev_desc)
                    device_state = None

                    if desc_type > 1:
                        # Read System 2 and System 7 manufacturer ID object
                        manufacturer = yield from protocol.apci_property_value_read(
                            target,
                            property_id=DEVICE_OBJECTS.get('PID_MANUFACTURER_ID'))
                        if isinstance(manufacturer, (str, bytes, bytearray)):
                            manufacturer = int.from_bytes(manufacturer, 'big')
                            manufacturer = knxmap.utils.get_manufacturer_by_id(manufacturer)

                        # Read the device state
                        device_state_data = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0060)
                        if device_state_data:
                            device_state = CemiFrame.unpack_cemi_runstate(
                                int.from_bytes(device_state_data, 'big'))

                        # Read the serial number object on System 2 and System 7 devices
                        serial = yield from protocol.apci_property_value_read(
                            target,
                            property_id=DEVICE_OBJECTS.get('PID_SERIAL_NUMBER'))
                        if isinstance(serial, (str, bytes, bytearray)):
                            serial = codecs.encode(serial, 'hex').decode().upper()

                        for object_index, props in OBJECTS.items():
                            x = collections.OrderedDict()
                            for k, v in props.items():
                                ret = yield from protocol.apci_property_value_read(
                                    target,
                                    property_id=v,
                                    object_index=object_index)
                                if ret:
                                    x[k.replace('PID_', '')] = codecs.encode(ret, 'hex')
                            if x:
                                properties[OBJECT_TYPES.get(object_index)] = x
                    else:
                        # Try to MemoryRead the manufacturer ID on System 1 devices.
                        # Note: System 1 devices do not support access controls, so
                        # an authorization request is not needed.
                        manufacturer = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0104,
                            read_count=1)
                        if isinstance(manufacturer, (str, bytes, bytearray)):
                            manufacturer = int.from_bytes(manufacturer, 'big')
                            manufacturer = knxmap.utils.get_manufacturer_by_id(manufacturer)

                        device_state_data = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0060)
                        if device_state_data:
                            device_state = codecs.encode(device_state_data, 'hex')

                        ret = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0105,
                            read_count=2)
                        if ret:
                            properties['Device Type'] = codecs.encode(ret, 'hex')

                        ret = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0101,
                            read_count=3)
                        if ret:
                            properties['ManData'] = codecs.encode(ret, 'hex')

                        ret = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0108,
                            read_count=1)
                        if ret:
                            properties['CheckLim'] = codecs.encode(ret, 'hex')

                        ret = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x01FE,
                            read_count=1)
                        if ret:
                            properties['User Program'] = codecs.encode(ret, 'hex')

                        start_addr = 0x0100
                        properties['EEPROM_DUMP'] = b''
                        for i in range(51):
                            ret = yield from protocol.apci_memory_read(
                                target,
                                memory_address=start_addr,
                                read_count=5)
                            if ret:
                                properties['EEPROM_DUMP'] += codecs.encode(ret, 'hex')
                            start_addr += 5

                    # Try to read group addresses
                    if desc_type ==7:
                        group_address_table = 0x4000
                    else:
                        group_address_table = 0x0116

                    if desc_type > 1 and not self.ignore_auth:
                        auth_level = yield from protocol.apci_authenticate(
                            target,
                            key=self.auth_key)
                        if auth_level > 0:
                            yield from protocol.tpci_disconnect(target)
                            queue.task_done()
                            LOGGER.error('Invalid authentication key for target %s' % target)
                            continue

                    ret = yield from protocol.apci_memory_read(
                        target,
                        memory_address=group_address_table,
                        read_count=1)
                    if ret and int.from_bytes(ret, 'big') > 1:
                        byte_count = (int.from_bytes(ret, 'big') * 2) + 1
                        address_table = yield from protocol.apci_memory_read(
                            target,
                            memory_address=group_address_table,
                            read_count=byte_count) # each address is 2 bytes long
                        if address_table:
                            properties['Group Addresses'] = []
                            ga = address_table[3:] # skip length and individual address
                            for addr in [ga[i:i + 2] for i in range(0, len(ga), 2)]:
                                properties['Group Addresses'].append(
                                    knxmap.utils.parse_knx_group_address(int.from_bytes(addr, 'big')))

                    if descriptor:
                        t = KnxBusTargetReport(
                            address=target,
                            medium=desc_medium,
                            type=desc_type,
                            version=desc_version,
                            device_serial=serial,
                            device_state=device_state,
                            manufacturer=manufacturer,
                            properties=properties)
                        self.bus_devices.add(t)

                    # Properly close the TPCI layer
                    yield from protocol.tpci_disconnect(target)

                queue.task_done()
        except asyncio.CancelledError:
            pass
        except asyncio.QueueEmpty:
            pass

    @asyncio.coroutine
    def _tunnel_connection(self, knx_gateway):
        """Try to establish a tunnel connection to the target.
        if the connection is successfully established, the
        resulting transport an protocol instances are added
        as a dict to the self.bus_connections[target.host]
        list."""
        future = asyncio.Future()
        transport, bus_protocol = yield from self.loop.create_datagram_endpoint(
            functools.partial(
                KnxTunnelConnection,
                future,
                ndp_defer_time=self.bus_timeout,
                knx_source=self.knx_source,
                nat_mode=self.nat_mode),
            remote_addr=(knx_gateway.host, knx_gateway.port))
        connected = yield from future
        if connected:
            self.bus_protocols.append(bus_protocol)
            self.bus_connections[knx_gateway.host].append({
                'transport': transport,
                'protocol': bus_protocol})

    @asyncio.coroutine
    def _bus_scan(self, knx_gateway, bus_targets):
        # Make sure the tunnel has been established
        queue = self.add_bus_queue(knx_gateway.host, bus_targets)
        connections = 1
        self.bus_connections[knx_gateway.host] = []
        if len(bus_targets) > 10:
            if len(knx_gateway.additional_individual_addresses) > 1:
                LOGGER.info('Additional individual addresses available')
                connections = len(knx_gateway.additional_individual_addresses)
            if self.max_connections and connections > self.max_connections:
                connections = self.max_connections
        connectors = [asyncio.Task(self._tunnel_connection(knx_gateway))
                      for _ in range(connections)]
        yield from asyncio.wait(connectors)
        LOGGER.info('Established %d connections to target %s' %
                    (len(self.bus_connections[knx_gateway.host]),
                     knx_gateway.host))
        workers = [asyncio.Task(self._knx_bus_worker(c.get('transport'),
                                                     c.get('protocol'),
                                                     knx_gateway),
                                loop=self.loop) for c in self.bus_connections[knx_gateway.host]]
        self.t0 = time.time()
        yield from queue.join()
        self.t1 = time.time()
        for w in workers:
            w.cancel()
        for c in self.bus_connections[knx_gateway.host]:
            c.get('protocol').knx_tunnel_disconnect()
        for i in self.bus_devices:
            knx_gateway.bus_devices.append(i)

        LOGGER.info('Bus scan took {} seconds'.format(self.t1 - self.t0))

    @asyncio.coroutine
    def scan(self, targets=None, desc_timeout=2, desc_retries=2, bus_timeout=2,
             bus_targets=None, bus_info=False, knx_source=None, auth_key=0xffffffff,
             configuration_reads=True, ignore_auth=False):
        """The function that will be called by run_until_complete(). This is the main coroutine."""
        if not isinstance(auth_key, int):
            try:
                auth_key = int(auth_key, 16)
                self.auth_key = auth_key
            except ValueError:
                LOGGER.debug('Invalid key, using the default')
        self.configuration_reads = configuration_reads
        self.knx_source = knx_source
        self.desc_timeout = desc_timeout
        self.desc_retries = desc_retries
        self.bus_timeout = bus_timeout
        self.bus_info = bus_info
        self.ignore_auth = ignore_auth
        if targets:
            self.set_targets(targets)
        if self.medium == 'net':
            workers = [asyncio.Task(self._knx_description_worker(), loop=self.loop)
                       for _ in range(self.max_workers
                                      if len(self.targets) > self.max_workers else len(self.targets))]
            self.t0 = time.time()
            yield from self.q.join()
            self.t1 = time.time()
            for w in workers:
                w.cancel()

            if bus_targets and self.knx_gateways:
                # Start scanning on the bus
                bus_scanners = [asyncio.Task(self._bus_scan(knx_gateway=g,
                                                            bus_targets=bus_targets),
                                             loop=self.loop) for g in self.knx_gateways]
                yield from asyncio.wait(bus_scanners)

            if not self.testing:
                for t in self.knx_gateways:
                    print_knx_target(t)
            LOGGER.info('Scan took {} seconds'.format(self.t1 - self.t0))

        elif self.medium == 'usb':
            if USB_SUPPORT:
                #bus_scanners = [asyncio.Task(self._bus_scan(bus_targets=bus_targets),
                #                         loop=self.loop) for _ in range(self.max_workers)]
                #yield from asyncio.wait(bus_scanners)

                from knxmap.usb.core import KnxUsbTransport, KnxHidReport
                try:
                    transport = KnxUsbTransport(vendor_id=0x147b,
                                                product_id=0x5120)
                except OSError:
                    LOGGER.error('Could not open USB device (try running KNXmap with superuser privileges)')
                    return

                frame = KnxEmi1Frame(knx_source='0.0.0',
                                     knx_destination='1.1.2')
                report = KnxHidReport(message_code=0x11,
                                      protocol_id=0x01,
                                      frame=frame.pack())
                # frame = bytearray(b'\x11\xb0\x00\x00\x00\x00\xe1\x01\x00')
                # report = KnxHidReport(message_code=0x11,
                #                       protocol_id=0x01,
                #                       frame=frame.pack())
                LOGGER.trace_outgoing(report)
                transport.write(report.report)
                time.sleep(1)
                r = transport.read()
                if r:
                    report = KnxHidReport(data=r)
                else:
                    print('GOT NO RESPONSE')
                for _ in range(5):
                    time.sleep(1)
                    r = transport.read()
                    if r:
                        report = KnxHidReport(data=r)
                    else:
                        print('GOT NO RESPONSE')
            else:
                LOGGER.error('USB support not available, install hidapi module')

    @asyncio.coroutine
    def group_writer(self, target, value=0, routing=False, desc_timeout=2,
                     desc_retries=2, iface=False):
        self.desc_timeout = desc_timeout
        self.desc_retries = desc_retries
        self.iface = iface
        workers = [asyncio.Task(self._knx_description_worker(), loop=self.loop)
                   for _ in range(self.max_workers if len(self.targets) > self.max_workers else len(self.targets))]
        self.t0 = time.time()
        yield from self.q.join()
        self.t1 = time.time()
        for w in workers:
            w.cancel()

        if self.knx_gateways:
            # TODO: make sure only a single gateway is supplied
            knx_gateway = self.knx_gateways[0]
        else:
            LOGGER.error('No valid KNX gateway found')
            return

        if routing:
            # Use KNX Routing to write group values
            if 'KNXnet/IP Routing' not in knx_gateway.supported_services:
                LOGGER.error('KNX gateway {gateway} does not support Routing'.format(
                    gateway=knx_gateway.host))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            struct.pack('256s', str.encode(self.iface)))
            # TODO: what if we have devices that access more advanced payloads?
            if isinstance(value, str):
                value = int(value)
            protocol = KnxRoutingConnection(target=target, value=value)
            waiter = asyncio.Future(loop=self.loop)
            transport = self.loop._make_datagram_transport(
                sock, protocol, ('224.0.23.12', 3671), waiter)
            try:
                # Wait until connection_made() has been called on the transport
                yield from waiter
            except asyncio.CancelledError:
                LOGGER.error('Creating multicast transport failed!')
                transport.close()
                return
        else:
            # Use KNX Tunnelling to write group values
            if 'KNXnet/IP Tunnelling' not in knx_gateway.supported_services:
                LOGGER.error('KNX gateway {gateway} does not support Routing'.format(
                    gateway=knx_gateway.host))
            future = asyncio.Future()
            transport, protocol = yield from self.loop.create_datagram_endpoint(
                functools.partial(KnxTunnelConnection, future, nat_mode=self.nat_mode),
                remote_addr=(knx_gateway.host, knx_gateway.port))
            self.bus_protocols.append(protocol)
            # Make sure the tunnel has been established
            connected = yield from future
            if connected:
                # TODO: what if we have devices that access more advanced payloads?
                if isinstance(value, str):
                    value = int(value)
                yield from protocol.apci_group_value_write(target, value=value)
                protocol.knx_tunnel_disconnect()

    @asyncio.coroutine
    def apci(self, target, desc_timeout=2, desc_retries=2, iface=False, args=None):
        self.desc_timeout = desc_timeout
        self.desc_retries = desc_retries
        self.iface = iface
        self.knx_source = args.knx_source
        workers = [asyncio.Task(self._knx_description_worker(), loop=self.loop)
                   for _ in range(self.max_workers if len(self.targets) > self.max_workers else len(self.targets))]
        self.t0 = time.time()
        yield from self.q.join()
        self.t1 = time.time()
        for w in workers:
            w.cancel()

        if self.knx_gateways:
            # TODO: make sure only a single gateway is supplied
            knx_gateway = self.knx_gateways[0]
        else:
            LOGGER.error('No valid KNX gateway found')
            return

        # Use KNX Tunnelling to write group values
        if 'KNXnet/IP Tunnelling' not in knx_gateway.supported_services:
            LOGGER.error('KNX gateway {gateway} does not support Routing'.format(
                gateway=knx_gateway.host))

        future = asyncio.Future()
        transport, protocol = yield from self.loop.create_datagram_endpoint(
            functools.partial(KnxTunnelConnection, future,
                              knx_source=self.knx_source, nat_mode=self.nat_mode),
            remote_addr=(knx_gateway.host, knx_gateway.port))
        self.bus_protocols.append(protocol)

        # Make sure the tunnel has been established
        connected = yield from future

        if connected:
            if args.apci_type == 'Memory_Read':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    dev_type = yield from protocol.get_device_type(target)
                    if not dev_type:
                        protocol.knx_tunnel_disconnect()
                        protocol.tpci_disconnect(target)
                        return
                    if dev_type > 1 and not args.ignore_auth:
                        auth_key = args.auth_key
                        if not isinstance(auth_key, int):
                            try:
                                auth_key = int(auth_key, 16)
                            except ValueError:
                                LOGGER.error('Invalid property ID')
                                protocol.knx_tunnel_disconnect()
                                protocol.tpci_disconnect(target)
                                return
                        auth_level = yield from protocol.apci_authenticate(
                            target,
                            key=auth_key)
                        if auth_level > 0:
                            LOGGER.error('Invalid authentication key')
                            protocol.knx_tunnel_disconnect()
                            protocol.tpci_disconnect(target)
                            return
                    memory_address = args.memory_address
                    if not isinstance(memory_address, int):
                        try:
                            memory_address = int(memory_address, 16)
                        except ValueError:
                            LOGGER.error('Invalid property ID')
                            protocol.knx_tunnel_disconnect()
                            protocol.tpci_disconnect(target)
                            return
                    data = yield from protocol.apci_memory_read(
                        target,
                        memory_address=memory_address,
                        read_count=args.read_count)
                    protocol.tpci_disconnect(target)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'Memory_Write':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    dev_type = yield from protocol.get_device_type(target)
                    if not dev_type:
                        protocol.knx_tunnel_disconnect()
                        protocol.tpci_disconnect(target)
                        return
                    if dev_type > 1:
                        auth_key = args.auth_key
                        if not isinstance(auth_key, int):
                            try:
                                auth_key = int(auth_key, 16)
                            except ValueError:
                                LOGGER.error('Invalid property ID')
                                protocol.knx_tunnel_disconnect()
                                protocol.tpci_disconnect(target)
                                return
                        auth_level = yield from protocol.apci_authenticate(
                            target,
                            key=auth_key)
                        if auth_level > 0:
                            LOGGER.error('Invalid authentication key')
                            protocol.knx_tunnel_disconnect()
                            protocol.tpci_disconnect(target)
                            return
                    memory_address = args.memory_address
                    memory_data = args.memory_data
                    if not isinstance(memory_address, int) or \
                            not isinstance(memory_data, bytes):
                        try:
                            memory_address = int(memory_address, 16)
                            memory_data = codecs.decode(memory_data, 'hex')
                        except ValueError:
                            LOGGER.error('Invalid property ID or write data')
                            protocol.knx_tunnel_disconnect()
                            protocol.tpci_disconnect(target)
                            return
                    data = yield from protocol.apci_memory_write(
                        target,
                        memory_address=memory_address,
                        write_count=args.read_count,
                        data=memory_data)
                    protocol.tpci_disconnect(target)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'Key_Write':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    dev_type = yield from protocol.get_device_type(target)
                    if not dev_type:
                        protocol.knx_tunnel_disconnect()
                        protocol.tpci_disconnect(target)
                        return
                    if dev_type > 1:
                        auth_key = args.auth_key
                        if not isinstance(auth_key, int):
                            try:
                                auth_key = int(auth_key, 16)
                            except ValueError:
                                LOGGER.error('Invalid property ID')
                                protocol.knx_tunnel_disconnect()
                                protocol.tpci_disconnect(target)
                                return
                        auth_level = yield from protocol.apci_authenticate(
                            target,
                            key=auth_key)
                        if auth_level > 0:
                            LOGGER.error('Invalid authentication key')
                            protocol.knx_tunnel_disconnect()
                            protocol.tpci_disconnect(target)
                            return
                    new_auth_key = args.new_auth_key
                    if not isinstance(new_auth_key, int):
                        try:
                            new_auth_key = int(new_auth_key, 16)
                        except ValueError:
                            LOGGER.error('Invalid property ID')
                            protocol.knx_tunnel_disconnect()
                            protocol.tpci_disconnect(target)
                            return
                    data = yield from protocol.apci_key_write(
                        target,
                        level=args.auth_level,
                        key=new_auth_key)
                    protocol.tpci_disconnect(target)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info('Authorization level: {}'.format(data))
            elif args.apci_type == 'PropertyValue_Read':
                property_id = args.property_id
                if not isinstance(property_id, int):
                    try:
                        property_id = int(property_id, 16)
                    except ValueError:
                        LOGGER.error('Invalid property ID')
                        protocol.knx_tunnel_disconnect()
                        protocol.tpci_disconnect(target)
                        return
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_property_value_read(
                        target,
                        object_index=args.object_index,
                        property_id=property_id,
                        num_elements=args.num_elements,
                        start_index=args.start_index)
                    protocol.tpci_disconnect(target)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'DeviceDescriptor_Read':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_device_descriptor_read(target)
                    protocol.tpci_disconnect(target)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'Authorize':
                auth_key = args.auth_key
                if not isinstance(auth_key, int):
                    try:
                        auth_key = int(auth_key, 16)
                    except ValueError:
                        LOGGER.error('Invalid property ID')
                        protocol.knx_tunnel_disconnect()
                        protocol.tpci_disconnect(target)
                        return
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_authenticate(
                        target,
                        key=auth_key)
                    protocol.tpci_disconnect(target)
                    if isinstance(data, (type(None), type(False))):
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info('Authorization level: {}'.format(data))
            elif args.apci_type == 'IndividualAddress_Read':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_individual_address_read(target)
                    protocol.tpci_disconnect(target)
                    if isinstance(data, (type(None), type(False))):
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info('Individual address: {}'.format(data))
            elif args.apci_type == 'UserManufacturerInfo_Read':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_user_manufacturer_info_read(target)
                    protocol.tpci_disconnect(target)
                    if isinstance(data, (type(None), type(False))):
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'Restart':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    yield from protocol.apci_restart(target)
                    protocol.tpci_disconnect(target)
            elif args.apci_type == 'Progmode':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    dev_type = yield from protocol.get_device_type(target)
                    if not dev_type:
                        protocol.knx_tunnel_disconnect()
                        protocol.tpci_disconnect(target)
                        return
                    if dev_type > 1:
                        auth_key = args.auth_key
                        if not isinstance(auth_key, int):
                            try:
                                auth_key = int(auth_key, 16)
                            except ValueError:
                                LOGGER.error('Invalid property ID')
                                protocol.knx_tunnel_disconnect()
                                protocol.tpci_disconnect(target)
                                return
                        auth_level = yield from protocol.apci_authenticate(
                            target,
                            key=auth_key)
                        if auth_level > 0:
                            LOGGER.error('Invalid authentication key')
                            protocol.knx_tunnel_disconnect()
                            protocol.tpci_disconnect(target)
                            return
                    data = yield from protocol.apci_memory_read(
                        target,
                        memory_address=0x0060,
                        read_count=args.read_count)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        data = int.from_bytes(data, 'big')
                        run_state = CemiFrame.unpack_cemi_runstate(data)
                        if args.toggle:
                            if run_state.get('PROG_MODE'):
                                run_state = CemiFrame.pack_cemi_runstate(
                                    prog_mode=False,
                                    link_layer_active=run_state.get('LINK_LAYER'),
                                    transport_layer_active=run_state.get('TRANSPORT_LAYER'),
                                    app_layer_active=run_state.get('APP_LAYER'),
                                    serial_interface_active=run_state.get('SERIAL_INTERFACE'),
                                    user_app_run=run_state.get('USER_APP'),
                                    bcu_download_mode=run_state.get('BC_DM'))
                            else:
                                run_state = CemiFrame.pack_cemi_runstate(
                                    prog_mode=True,
                                    link_layer_active=run_state.get('LINK_LAYER'),
                                    transport_layer_active=run_state.get('TRANSPORT_LAYER'),
                                    app_layer_active=run_state.get('APP_LAYER'),
                                    serial_interface_active=run_state.get('SERIAL_INTERFACE'),
                                    user_app_run=run_state.get('USER_APP'),
                                    bcu_download_mode=run_state.get('BC_DM'))
                            data = yield from protocol.apci_memory_write(
                                target,
                                memory_address=0x0060,
                                data=struct.pack('!B', run_state))
                            if not data:
                                LOGGER.debug('No data received')
                            else:
                                LOGGER.info(codecs.encode(data, 'hex'))
                        else:
                            if run_state.get('PROG_MODE'):
                                LOGGER.info('Programming mode ENABLED')
                            else:
                                LOGGER.info('Programming mode disabled')
                    protocol.tpci_disconnect(target)
            elif args.apci_type == 'GroupValue_Write':
                if not hasattr(args, 'value') or args.value is None:
                    LOGGER.error('Invalid parameters')
                    protocol.knx_tunnel_disconnect()
                    return
                if isinstance(args.value, str):
                    value = int(args.value)
                else:
                    value = args.value
                yield from protocol.apci_group_value_write(target, value=value)

            protocol.knx_tunnel_disconnect()