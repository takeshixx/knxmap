import asyncio
import binascii
import collections
import codecs
import logging
import os
import socket
import struct
import sys
import time
import functools
try:
    # Python 3.4
    from asyncio import JoinableQueue as Queue
except ImportError:
    # Python 3.5 renamed it to Queue
    from asyncio import Queue

from libknxmap.core import *
from libknxmap.messages import *
from libknxmap.gateway import *
from libknxmap.manufacturers import *
from libknxmap.targets import *
from libknxmap.bus.tunnel import KnxTunnelConnection
from libknxmap.bus.monitor import KnxBusMonitor

__all__ = ['KnxScanner']

LOGGER = logging.getLogger(__name__)


class KnxScanner:
    """The main scanner instance that takes care of scheduling workers for the targets."""
    def __init__(self, targets=None, max_workers=100, loop=None, ):
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
                    # DeviceDescriptorRead
                    tunnel_request = protocol.make_tunnel_request(target)
                    tunnel_request.apci_device_descriptor_read(sequence=protocol.tpci_seq_counts.get(target))
                    descriptor = yield from protocol.send_data(tunnel_request.get_message(), target)

                    if not isinstance(descriptor, KnxTunnellingRequest) or not \
                            descriptor.body.get('cemi').get('apci') == CEMI_APCI_TYPES.get('A_DeviceDescriptor_Response'):
                        tunnel_request = protocol.make_tunnel_request(target)
                        tunnel_request.tpci_unnumbered_control_data('DISCONNECT')
                        protocol.send_data(tunnel_request.get_message(), target)
                        queue.task_done()
                        continue

                    ret = yield from protocol.tpci_send_ncd(target)
                    if not ret:
                        # TODO: if this is False, can we continue with the KNX connection?
                        LOGGER.error('ERROR OCCURED AFTER READING DEVICE DESCRIPTOR')

                    if isinstance(descriptor, KnxTunnellingRequest) and \
                                descriptor.body.get('cemi').get('apci') == \
                                CEMI_APCI_TYPES.get('A_DeviceDescriptor_Response') and \
                                not self.bus_info:
                            t = KnxBusTargetReport(address=target)
                            self.bus_devices.add(t)
                            tunnel_request = protocol.make_tunnel_request(target)
                            tunnel_request.tpci_unnumbered_control_data('DISCONNECT')
                            protocol.send_data(tunnel_request.get_message(), target)
                            queue.task_done()
                            continue

                    dev_desc = struct.unpack('!H', descriptor.body.get('cemi').get('data'))[0]
                    desc_medium, desc_type, desc_version = KnxMessage.parse_device_descriptor(dev_desc)
                    manufacturer = None
                    serial = None

                    if desc_type > 1:
                        # Read System 2 and System 7 manufacturer ID object
                        tunnel_request = protocol.make_tunnel_request(target)
                        tunnel_request.apci_property_value_read(
                            sequence=protocol.tpci_seq_counts.get(target),
                            object_index=0,
                            property_id=DEVICE_OBJECTS.get('PID_MANUFACTURER_ID'))
                        manufacturer = yield from protocol.send_data(tunnel_request.get_message(), target)
                        if isinstance(manufacturer, KnxTunnellingRequest):
                            if manufacturer.body.get('cemi').get('data'):
                                print(manufacturer.body.get('cemi'))
                                manufacturer = manufacturer.body.get('cemi').get('data')[4:]
                            else:
                                LOGGER.info('manufacturer: data not included')
                        else:
                            LOGGER.info('NOT KnxTunnellingRequest: {}'.format(manufacturer))
                    else:
                        # Try to MemoryRead the manufacturer ID on System 1 devices.
                        # Note: System 1 devices do not support access controls, so
                        # an authorization request is not needed.
                        tunnel_request = protocol.make_tunnel_request(target)
                        tunnel_request.apci_memory_read(
                            sequence=protocol.tpci_seq_counts.get(target),
                            memory_address=0x0104,
                            read_count=1)
                        manufacturer = yield from protocol.send_data(tunnel_request.get_message(), target)
                        if isinstance(manufacturer, KnxTunnellingRequest):
                            if manufacturer.body.get('cemi').get('data'):
                                manufacturer = manufacturer.body.get('cemi').get('data')[2:]
                            else:
                                LOGGER.info('manufacturer: data not included')
                        else:
                            LOGGER.info('NOT KnxTunnellingRequest: {}'.format(manufacturer))

                    ret = yield from protocol.tpci_send_ncd(target)
                    if not ret:
                        manufacturer = 'COULD NOT READ MANUFACTURER'
                    else:
                        if isinstance(manufacturer, (str, bytes)):
                            manufacturer = int.from_bytes(manufacturer, 'big')
                            manufacturer = get_manufacturer_by_id(manufacturer)

                    if desc_type == 1:
                        # MemoryRead application program
                        tunnel_request = protocol.make_tunnel_request(target)
                        tunnel_request.apci_memory_read(
                            sequence=protocol.tpci_seq_counts.get(target),
                            memory_address=0x0105,
                            read_count=4)
                        device_id = yield from protocol.send_data(tunnel_request.get_message(), target)
                        if isinstance(device_id, KnxTunnellingRequest):
                            if device_id.body.get('cemi').get('data'):
                                device_id = device_id.body.get('cemi').get('data')[2:]
                            else:
                                LOGGER.info('application_program: data not included')
                        else:
                            LOGGER.info('NOT KnxTunnellingRequest: {}'.format(device_id))
                        yield from protocol.tpci_send_ncd(target)

                        # TODO: is this comparable to an actual serial?
                        serial = codecs.encode(device_id, 'hex')

                    if desc_type > 1:
                        # Read the serial number object on System 2 and System 7 devices
                        tunnel_request = protocol.make_tunnel_request(target)
                        tunnel_request.apci_property_value_read(
                            sequence=protocol.tpci_seq_counts.get(target),
                            object_index=0,
                            property_id=DEVICE_OBJECTS.get('PID_SERIAL_NUMBER'))
                        serial = yield from protocol.send_data(tunnel_request.get_message(), target)
                        if isinstance(serial, KnxTunnellingRequest):
                            if serial.body.get('cemi').get('data'):
                                serial = serial.body.get('cemi').get('data')[4:]
                            else:
                                LOGGER.info('serial: data not included')
                        else:
                            LOGGER.info('NOT KnxTunnellingRequest: {}'.format(serial))

                        ret = yield from protocol.tpci_send_ncd(target)
                        if not ret:
                            serial = 'COULD NOT READ SERIAL'
                        else:
                            if isinstance(serial, (str, bytes)):
                                serial = codecs.encode(serial, 'hex').decode().upper()

                        # DEV

                        # PropertyValueRead
                        # tunnel_request = protocol.make_tunnel_request(target)
                        # tunnel_request.apci_property_value_read(
                        #     sequence=protocol.tpci_seq_counts.get(target),
                        #     object_index=2,
                        #     num_elements=1,
                        #     start_index=0,
                        #     property_id=52)
                        # additional = yield from protocol.send_data(tunnel_request.get_message(), target)
                        # print("ADDITIONAL ADDRESSES")
                        # print(additional)
                        # if isinstance(additional, KnxTunnellingRequest):
                        #     print(additional.body)
                        # else:
                        #     LOGGER.info('NOT KnxTunnellingRequest: {}'.format(additional))
                        #
                        # # NCD
                        # ret = yield from protocol.tpci_send_ncd(target)
                        #
                        # if not ret:
                        #     serial = 'COULD NOT READ ADDITIONAL INDIVIDUAL ADDRESSES'
                        # else:
                        #     if isinstance(serial, (str, bytes)):
                        #         serial = codecs.encode(serial, 'hex').decode().upper()


                        # Memory read device state
                        # tunnel_request = protocol.make_tunnel_request(target)
                        # tunnel_request.apci_memory_read(
                        #     sequence=protocol.tpci_seq_counts.get(target),
                        #     memory_address=0x0060,
                        #     read_count=1)
                        # run_state = yield from protocol.send_data(tunnel_request.get_message(), target)
                        # yield from protocol.tpci_send_ncd(target)
                        # if isinstance(run_state, KnxTunnellingRequest):
                        #     if run_state.body.get('cemi').get('data'):
                        #         run_state = run_state.body.get('cemi').get('data')[2:]
                        #     else:
                        #         LOGGER.info('run_state: data not included')
                        # else:
                        #     LOGGER.info('NOT KnxTunnellingRequest: {}'.format(run_state))
                        #
                        # print("RUN STATE")
                        # print(run_state)

                        # for obj in range(1,20):
                        #     for prop in range(1,150):
                        #         tunnel_request = protocol.make_tunnel_request(target)
                        #         tunnel_request.apci_property_value_read(
                        #             sequence=protocol.tpci_seq_counts.get(target),
                        #             object_index=obj,
                        #             start_index=1,
                        #             property_id=prop)
                        #         prop_ret = yield from protocol.send_data(tunnel_request.get_message(), target)
                        #         if isinstance(prop_ret, KnxTunnellingRequest):
                        #             print("--- obj: {}, prop: {}".format(obj, prop))
                        #             if prop_ret.body:
                        #                 #print(prop_ret.body)
                        #                 print("property data: {}".format(prop_ret.body.get('cemi').get('data')[2:]))
                        #             print("---")
                        #         else:
                        #             LOGGER.debug('unknown response for obj: {}, prop: {}'.format(obj, prop))
                        #
                        #         # NCD
                        #         ret = yield from protocol.tpci_send_ncd(target)

                    if descriptor:
                        t = KnxBusTargetReport(
                            address=target,
                            medium=desc_medium,
                            type=desc_type,
                            version=desc_version,
                            device_serial=serial,
                            manufacturer=manufacturer)
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

        # DEV: test configuration request
        # future = asyncio.Future()
        # bus_con = KnxTunnelConnection(future, connection_type=0x03) # DEVICE_MGMT_CONNECTION
        # transport, bus_protocol = yield from self.loop.create_datagram_endpoint(
        #     lambda: bus_con, remote_addr=(knx_gateway.host, knx_gateway.port))
        # self.bus_protocols.append(bus_protocol)
        #
        # connected = yield from future
        # if connected:
        #     conf_req = bus_protocol.make_configuration_request()
        #     print("bla")
        #     print(conf_req)
        #     bla = conf_req.get_message()
        #     print(bla)
        #     print("blubb")
        #     resp = yield from bus_protocol.send_data(conf_req.get_message())
        #     LOGGER.info('CONFIGURATION RESPONSE')
        #     print(resp)

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
        """Send a KnxDescription request to see if target is a KNX device."""
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
                            KNX_SERVICES[k] for k,v in
                            response.body.get('dib_supp_sv_families').get('families').items()],
                        bus_devices=[])

                    self.knx_gateways.append(t)
                self.q.task_done()
        except (asyncio.CancelledError, asyncio.QueueEmpty) as e:
            pass

    @asyncio.coroutine
    def scan(self, targets=None, search_mode=False, search_timeout=5, iface=None,
             desc_timeout=2, desc_retries=2, bus_targets=None, bus_info=False,
             bus_monitor_mode=False, group_monitor_mode=False):
        """The function that will be called by run_until_complete(). This is the main coroutine."""
        if targets:
            self.set_targets(targets)

        if search_mode:
            self.iface = iface
            self.search_timeout = search_timeout
            LOGGER.info('Make sure there are no filtering rules that drop UDP multicast packets!')
            yield from self.search_gateways()
            for t in self.knx_gateways:
                self.print_knx_target(t)
            LOGGER.info('Searching done')

        elif bus_monitor_mode or group_monitor_mode:
            LOGGER.info('Starting bus monitor')
            future = asyncio.Future()
            transport, protocol = yield from self.loop.create_datagram_endpoint(
                functools.partial(KnxBusMonitor, future, group_monitor=group_monitor_mode),
                remote_addr=list(self.targets)[0])
            self.bus_protocols.append(protocol)
            yield from future
            LOGGER.info('Stopping bus monitor')

        else:
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
