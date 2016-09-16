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

from libknxmap.data.constants import *
from libknxmap.messages import *
from libknxmap.gateway import *
from libknxmap.manufacturers import *
from libknxmap.targets import *
from libknxmap.bus.tunnel import KnxTunnelConnection
from libknxmap.bus.router import KnxRoutingConnection
from libknxmap.bus.monitor import KnxBusMonitor

__all__ = ['KnxMap']

LOGGER = logging.getLogger(__name__)


class KnxMap:
    """The main scanner instance that takes care of scheduling workers for the targets."""

    def __init__(self, targets=None, max_workers=100, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        # The number of concurrent workers for discovering KNXnet/IP gateways
        self.max_workers = max_workers
        # q contains all KNXnet/IP gateways
        self.q = Queue(loop=self.loop)
        # bus_queues is a dict containing a bus queue for each KNXnet/IP gateway
        self.bus_queues = dict()
        # bus_protocols is a list of all bus protocol instances for proper connection shutdown
        self.bus_protocols = list()
        # knx_gateways is a list of KnxTargetReport objects, one for each found KNXnet/IP gateway
        self.knx_gateways = list()
        # bus_devices is a list of KnxBusTargetReport objects, one for each found bus device
        self.bus_devices = set()
        self.bus_info = False
        self.t0 = time.time()
        self.t1 = None
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
    def bruteforce_auth_key(self, knx_gateway, target):
        if isinstance(target, set):
            target = list(target)[0]
        future = asyncio.Future()
        transport, protocol = yield from self.loop.create_datagram_endpoint(
            functools.partial(KnxTunnelConnection, future),
            remote_addr=(knx_gateway[0], knx_gateway[1]))
        self.bus_protocols.append(protocol)

        # Make sure the tunnel has been established
        connected = yield from future
        alive = yield from protocol.tpci_connect(target)

        # Bruteforce the key via A_Authorize_Request messages
        # for key in range(0, 0xffffffff):
        for key in [0x11223344, 0x12345678, 0x00000000, 0x87654321, 0x11111111, 0xffffffff]:
            access_level = yield from protocol.apci_authenticate(target, key)
            if access_level == 0:
                print("GOT THE KEY: {}".format(format(key, '08x')))
                break

    @asyncio.coroutine
    def knx_bus_worker(self, transport, protocol, queue):
        """A worker for communicating with devices on the bus."""
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
                    desc_medium, desc_type, desc_version = KnxMessage.parse_device_descriptor(dev_desc)

                    if desc_type > 1:
                        # Read System 2 and System 7 manufacturer ID object
                        manufacturer = yield from protocol.apci_property_value_read(
                            target,
                            property_id=DEVICE_OBJECTS.get('PID_MANUFACTURER_ID'))
                        if isinstance(manufacturer, (str, bytes)):
                            manufacturer = int.from_bytes(manufacturer, 'big')
                            manufacturer = get_manufacturer_by_id(manufacturer)

                        # Read the device state
                        device_state = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0060)
                        if device_state:
                            properties['DEVICE_STATE'] = KnxMessage.unpack_cemi_runstate(
                                int.from_bytes(device_state, 'big'))

                        # Read the serial number object on System 2 and System 7 devices
                        serial = yield from protocol.apci_property_value_read(
                            target,
                            property_id=DEVICE_OBJECTS.get('PID_SERIAL_NUMBER'))
                        if isinstance(serial, (str, bytes)):
                            serial = codecs.encode(serial, 'hex').decode().upper()

                        # DEV - group value write
                        # r = yield from protocol.apci_group_value_write('0.0.4', value=1)
                        # r = yield from protocol.apci_group_value_write('0.0.4', value=0)
                        # r = yield from protocol.apci_group_value_write('0.0.4', value=1)
                        # r = yield from protocol.apci_group_value_write('0.0.4', value=0)
                        # r = yield from protocol.apci_group_value_write('0.0.4', value=1)
                        # r = yield from protocol.apci_group_value_write('0.0.4', value=0)

                        # If we want to authenticate
                        # auth_level = yield from protocol.apci_authenticate(
                        #     target,
                        #     key=self.auth_key)

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
                        if isinstance(manufacturer, (str, bytes)):
                            manufacturer = int.from_bytes(manufacturer, 'big')
                            manufacturer = get_manufacturer_by_id(manufacturer)

                        device_state = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0060)
                        if device_state:
                            properties['DEVICE_STATE'] = codecs.encode(device_state, 'hex')

                        ret = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0105,
                            read_count=2)
                        if ret:
                            properties['DevTyp'] = codecs.encode(ret, 'hex')

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
                            properties['UsrPrg'] = codecs.encode(ret, 'hex')

                        ret = yield from protocol.apci_memory_read(
                            target,
                            memory_address=0x0116,
                            read_count=4)
                        if ret:
                            properties['AdrTab'] = codecs.encode(ret, 'hex')

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

                    if descriptor:
                        t = KnxBusTargetReport(
                            address=target,
                            medium=desc_medium,
                            type=desc_type,
                            version=desc_version,
                            device_serial=serial,
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
    def bus_scan(self, knx_gateway, bus_targets):
        queue = self.add_bus_queue(knx_gateway.host, bus_targets)
        LOGGER.info('Scanning {} bus device(s) on {}'.format(queue.qsize(), knx_gateway.host))
        future = asyncio.Future()
        transport, bus_protocol = yield from self.loop.create_datagram_endpoint(
            functools.partial(KnxTunnelConnection, future),
            remote_addr=(knx_gateway.host, knx_gateway.port))
        self.bus_protocols.append(bus_protocol)

        # Make sure the tunnel has been established
        connected = yield from future

        if connected:
            workers = [asyncio.Task(self.knx_bus_worker(transport, bus_protocol, queue), loop=self.loop)]
            self.t0 = time.time()
            yield from queue.join()
            self.t1 = time.time()
            for w in workers:
                w.cancel()
            bus_protocol.knx_tunnel_disconnect()

        for i in self.bus_devices:
            knx_gateway.bus_devices.append(i)

        LOGGER.info('Bus scan took {} seconds'.format(self.t1 - self.t0))

    @asyncio.coroutine
    def knx_search_worker(self):
        """Send a KnxSearch request to see if target is a KNX device."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, struct.pack('256s', str.encode(self.iface)))

            protocol = KnxGatewaySearch()
            waiter = asyncio.Future(loop=self.loop)
            transport = self.loop._make_datagram_transport(
                sock, protocol, ('224.0.23.12', 3671), waiter)

            try:
                # Wait until connection_made() has been called on the transport
                yield from waiter
            except:
                LOGGER.error('Creating multicast transport failed!')
                transport.close()
                return

            # Wait SEARCH_TIMEOUT seconds for responses to our multicast packets
            yield from asyncio.sleep(self.search_timeout)

            if protocol.responses:
                # If protocol received SEARCH_RESPONSE packets, print them
                for response in protocol.responses:
                    peer = response[0]
                    response = response[1]
                    t = KnxTargetReport(
                        host=peer[0],
                        port=peer[1],
                        mac_address=response.body.get('dib_dev_info').get('knx_mac_address'),
                        knx_address=response.body.get('dib_dev_info').get('knx_address'),
                        device_serial=response.body.get('dib_dev_info').get('knx_device_serial'),
                        friendly_name=response.body.get('dib_dev_info').get('device_friendly_name'),
                        device_status=response.body.get('dib_dev_info').get('device_status'),
                        knx_medium=response.body.get('dib_dev_info').get('knx_medium'),
                        project_install_identifier=response.body.get('dib_dev_info').get('project_install_identifier'),
                        supported_services=[
                            KNX_SERVICES[k] for k, v in
                            response.body.get('dib_supp_sv_families').get('families').items()],
                        bus_devices=[])

                    self.knx_gateways.append(t)
        except asyncio.CancelledError:
            pass

    @asyncio.coroutine
    def search_gateways(self):
        self.t0 = time.time()
        yield from asyncio.ensure_future(asyncio.Task(self.knx_search_worker(), loop=self.loop))
        self.t1 = time.time()
        LOGGER.info('Scan took {} seconds'.format(self.t1 - self.t0))

    @asyncio.coroutine
    def knx_description_worker(self):
        """Send a KnxDescription request to see if target is a KNX device."""
        try:
            while True:
                target = self.q.get_nowait()
                LOGGER.debug('Scanning {}'.format(target))
                for _try in range(self.desc_retries):
                    LOGGER.debug('Sending {}. KnxDescriptionRequest to {}'.format(_try, target))
                    future = asyncio.Future()
                    yield from self.loop.create_datagram_endpoint(
                        functools.partial(KnxGatewayDescription, future, timeout=self.desc_timeout),
                        remote_addr=target)
                    response = yield from future
                    if response:
                        break

                if response and isinstance(response, KnxDescriptionResponse):
                    t = KnxTargetReport(
                        host=target[0],
                        port=target[1],
                        mac_address=response.body.get('dib_dev_info').get('knx_mac_address'),
                        knx_address=response.body.get('dib_dev_info').get('knx_address'),
                        device_serial=response.body.get('dib_dev_info').get('knx_device_serial'),
                        friendly_name=response.body.get('dib_dev_info').get('device_friendly_name'),
                        device_status=response.body.get('dib_dev_info').get('device_status'),
                        knx_medium=response.body.get('dib_dev_info').get('knx_medium'),
                        project_install_identifier=response.body.get('dib_dev_info').get('project_install_identifier'),
                        supported_services=[
                            KNX_SERVICES[k] for k, v in
                            response.body.get('dib_supp_sv_families').get('families').items()],
                        bus_devices=[])

                    self.knx_gateways.append(t)
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
    def search(self, search_timeout=5, iface=None):
        self.iface = iface
        self.search_timeout = search_timeout
        LOGGER.info('Make sure there are no filtering rules that drop UDP multicast packets!')
        yield from self.search_gateways()
        for t in self.knx_gateways:
            print_knx_target(t)
        LOGGER.info('Searching done')

    @asyncio.coroutine
    def brute(self, targets=None, bus_target=None):
        if targets:
            self.set_targets(targets)
        tasks = [asyncio.Task(self.bruteforce_auth_key(t, bus_target), loop=self.loop) for t in self.targets]
        yield from asyncio.wait(tasks)

    @asyncio.coroutine
    def scan(self, targets=None, desc_timeout=2, desc_retries=2,
             bus_targets=None, bus_info=False, auth_key=0xffffffff):
        """The function that will be called by run_until_complete(). This is the main coroutine."""
        self.auth_key = auth_key
        if targets:
            self.set_targets(targets)

        self.desc_timeout = desc_timeout
        self.desc_retries = desc_retries
        workers = [asyncio.Task(self.knx_description_worker(), loop=self.loop)
                   for _ in range(self.max_workers if len(self.targets) > self.max_workers else len(self.targets))]
        self.t0 = time.time()
        yield from self.q.join()
        self.t1 = time.time()
        for w in workers:
            w.cancel()

        if bus_targets and self.knx_gateways:
            self.bus_info = bus_info
            bus_scanners = [asyncio.Task(self.bus_scan(g, bus_targets), loop=self.loop) for g in self.knx_gateways]
            yield from asyncio.wait(bus_scanners)
        else:
            LOGGER.info('Scan took {} seconds'.format(self.t1 - self.t0))

        for t in self.knx_gateways:
            print_knx_target(t)

    @asyncio.coroutine
    def group_writer(self, target, value=0, routing=False, desc_timeout=2,
                     desc_retries=2, iface=False):
        self.desc_timeout = desc_timeout
        self.desc_retries = desc_retries
        self.iface = iface
        workers = [asyncio.Task(self.knx_description_worker(), loop=self.loop)
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
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, struct.pack('256s', str.encode(self.iface)))

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
            except:
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
                functools.partial(KnxTunnelConnection, future),
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
        workers = [asyncio.Task(self.knx_description_worker(), loop=self.loop)
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
            functools.partial(KnxTunnelConnection, future),
            remote_addr=(knx_gateway.host, knx_gateway.port))
        self.bus_protocols.append(protocol)

        # Make sure the tunnel has been established
        connected = yield from future

        if connected:
            if args.apci_type == 'Memory_Read':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    descriptor = yield from protocol.apci_device_descriptor_read(target)
                    if not descriptor:
                        LOGGER.debug('Device not alive')
                        protocol.knx_tunnel_disconnect()
                        return
                    dev_desc = struct.unpack('!H', descriptor)[0]
                    if dev_desc > 1:
                        auth_key = args.auth_key
                        if not isinstance(auth_key, int):
                            try:
                                auth_key = int(auth_key, 16)
                            except ValueError:
                                LOGGER.error('Invalid property ID')
                                protocol.knx_tunnel_disconnect()
                                return
                        auth_level = yield from protocol.apci_authenticate(
                            target,
                            key=auth_key)
                        if auth_level > 0:
                            LOGGER.error('Invalid authentication key')
                            protocol.knx_tunnel_disconnect()
                            return
                    memory_address = args.memory_address
                    if not isinstance(memory_address, int):
                        try:
                            memory_address = int(memory_address, 16)
                        except ValueError:
                            LOGGER.error('Invalid property ID')
                            protocol.knx_tunnel_disconnect()
                            return
                    data = yield from protocol.apci_memory_read(
                        target,
                        memory_address=memory_address,
                        read_count=args.read_count)
                    yield from protocol.tpci_disconnect(target)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'Memory_Write':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    descriptor = yield from protocol.apci_device_descriptor_read(target)
                    if not descriptor:
                        LOGGER.debug('Device not alive')
                        protocol.knx_tunnel_disconnect()
                        return
                    dev_desc = struct.unpack('!H', descriptor)[0]
                    if dev_desc > 1:
                        auth_key = args.auth_key
                        if not isinstance(auth_key, int):
                            try:
                                auth_key = int(auth_key, 16)
                            except ValueError:
                                LOGGER.error('Invalid property ID')
                                protocol.knx_tunnel_disconnect()
                                return
                        auth_level = yield from protocol.apci_authenticate(
                            target,
                            key=auth_key)
                        if auth_level > 0:
                            LOGGER.error('Invalid authentication key')
                            protocol.knx_tunnel_disconnect()
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
                            return
                    data = yield from protocol.apci_memory_write(
                        target,
                        memory_address=memory_address,
                        write_count=args.read_count,
                        data=memory_data)
                    yield from protocol.tpci_disconnect(target)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'Key_Write':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    descriptor = yield from protocol.apci_device_descriptor_read(target)
                    if not descriptor:
                        LOGGER.debug('Device not alive')
                        protocol.knx_tunnel_disconnect()
                        return
                    dev_desc = struct.unpack('!H', descriptor)[0]
                    if dev_desc > 1:
                        auth_key = args.auth_key
                        if not isinstance(auth_key, int):
                            try:
                                auth_key = int(auth_key, 16)
                            except ValueError:
                                LOGGER.error('Invalid property ID')
                                protocol.knx_tunnel_disconnect()
                                return
                        auth_level = yield from protocol.apci_authenticate(
                            target,
                            key=auth_key)
                        if auth_level > 0:
                            LOGGER.error('Invalid authentication key')
                            protocol.knx_tunnel_disconnect()
                            return
                    new_auth_key = args.new_auth_key
                    if not isinstance(new_auth_key, int):
                        try:
                            new_auth_key = int(new_auth_key, 16)
                        except ValueError:
                            LOGGER.error('Invalid property ID')
                            protocol.knx_tunnel_disconnect()
                            return
                    data = yield from protocol.apci_key_write(
                        target,
                        level=args.auth_level,
                        key=new_auth_key)
                    yield from protocol.tpci_disconnect(target)
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
                        return
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_property_value_read(
                        target,
                        object_index=args.object_index,
                        property_id=property_id,
                        num_elements=args.num_elements,
                        start_index=args.start_index)
                    yield from protocol.tpci_disconnect(target)
                    if not data:
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'DeviceDescriptor_Read':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_device_descriptor_read(target)
                    yield from protocol.tpci_disconnect(target)
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
                        return
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_authenticate(
                        target,
                        key=auth_key)
                    yield from protocol.tpci_disconnect(target)
                    if isinstance(data, (type(None), type(False))):
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info('Authorization level: {}'.format(data))
            elif args.apci_type == 'IndividualAddress_Read':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_individual_address_read(target)
                    yield from protocol.tpci_disconnect(target)
                    if isinstance(data, (type(None), type(False))):
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info('Individual address: {}'.format(data))
            elif args.apci_type == 'UserManufacturerInfo_Read':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    data = yield from protocol.apci_user_manufacturer_info_read(target)
                    yield from protocol.tpci_disconnect(target)
                    if isinstance(data, (type(None), type(False))):
                        LOGGER.debug('No data received')
                    else:
                        LOGGER.info(codecs.encode(data, 'hex'))
            elif args.apci_type == 'Restart':
                alive = yield from protocol.tpci_connect(target)
                if alive:
                    yield from protocol.apci_restart(target)
                    yield from protocol.tpci_disconnect(target)
            elif args.apci_type == 'GroupValue_Write':
                if not hasattr(args, 'value') or args.value is None:
                    LOGGER.error('Invalid parameters')
                    protocol.knx_tunnel_disconnect()
                    return
                if isinstance(args.value, str):
                    value = int(args.value)
                yield from protocol.apci_group_value_write(target, value=value)


            protocol.knx_tunnel_disconnect()