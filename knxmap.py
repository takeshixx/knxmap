#! /usr/bin/env python3
import argparse
import binascii
import collections
import logging
import os
import socket
import struct
import sys
import time

import libknx

# asyncio requires at least Python 3.3
if sys.version_info.major < 3 or \
    (sys.version_info.major > 2 and
    sys.version_info.minor < 3):
    print('At least Python version 3.3 is required to run this script!')
    sys.exit(1)

try:
    # Python 3.4 ships with asyncio in the standard libraries. Users with Python 3.3
    # need to install it, e.g.: pip install asyncio
    import asyncio
except ImportError:
    print('Please install the asyncio module!')
    sys.exit(1)

try:
    # Python 3.4
    from asyncio import JoinableQueue as Queue
except ImportError:
    # Python 3.5 renamed it to Queue
    from asyncio import Queue

# Check if the ipaddress module is available for better target parsing support.
MOD_IPADDRESS = False
try:
    import ipaddress
    MOD_IPADDRESS = True
except ImportError:
    pass

LOGGER = logging.getLogger(__name__)

# TODO: create proper arguments
# TODO: add subcommands for scanning modes
ARGS = argparse.ArgumentParser(description="KNX Scanner")
ARGS.add_argument(
    'targets', nargs='*',
    default=[], help='Target hostnames/IP addresses')
ARGS.add_argument(
    '-v', '--verbose', action='count', dest='level',
    default=2, help='Verbose logging (repeat for more verbose)')
ARGS.add_argument(
    '-q', '--quiet', action='store_const', const=0, dest='level',
    default=2, help='Only log errors')
ARGS.add_argument(
    '-p', '--port', action='store', dest='port', type=int,
    default=3671, help='UDP port to be scanned')
ARGS.add_argument(
    '--workers', action='store', type=int, metavar='N',
    default=10, help='Limit concurrent workers')
ARGS.add_argument(
    '-i', '--interface', action='store', dest='iface',
    default=None, help='Interface to be used')
ARGS.add_argument(
    '--search', action='store_true', dest='search_mode',
    default=False, help='Find local KNX gateways via search requests')
ARGS.add_argument(
    '--search-timeout', action='store', dest='search_timeout', type=int,
    default=5, help='Timeout in seconds for multicast responses')
ARGS.add_argument(
    '--bus', action='store_true', dest='bus_mode',
    default=False, help='Scan bus on KNXnet/IP gateway')
ARGS.add_argument(
    '--bus-monitor', action='store_true', dest='monitor_mode',
    default=False, help='Monitor bus messages via KNXnet/IP gateway')

KnxTargetReport = collections.namedtuple(
    'KnxTargetReport',
    ['host',
    'port',
    'mac_address',
    'knx_address',
    'device_serial',
    'friendly_name',
    'device_status',
    'supported_services',
    'bus_devices'])


class KnxScanner():
    """The main scanner instance that takes care of scheduling workers for the targets."""

    def __init__(self, targets=None, max_workers=10, loop=None, ):
        self.loop = loop or asyncio.get_event_loop()
        self.max_workers = max_workers
        # the Queue contains all targets
        self.q = Queue(loop=self.loop)

        self.gateway_queue = Queue(loop=self.loop)
        self.bus_queue = Queue(loop=self.loop)

        # DEV: add dev targets
        self.dev_add_knx_targets(
            self.dev_knx_address_range())

        if targets:
            self.targets = targets
        else:
            self.targets = set()
        self.alive_targets = set()
        self.knx_gateways = list()
        self.bus_devices = list()

        for target in targets:
            self.add_target(target)

        # save some timing information
        self.t0 = time.time()
        self.t1 = None

    @staticmethod
    def dev_knx_address_range():
        """A helper function that returns bus targets.
        Either return t (complete KNXnet/IP address space) or any list of targets."""
        t = []
        for i in [0, 1, 2]:
            for ii in [0, 1, 2]:
                for iii in range(1, 16):
                    t.append('{}.{}.{}'.format(i, ii, iii))

        return ['0.0.1']

        return ['0.0.1',
                '0.0.2',
                '0.0.3',
                '0.0.4',
                '1.1.5',
                '15.15.255']

    def dev_add_knx_targets(self, targets):
        for t in targets:
            self.bus_queue.put_nowait(t)

    def dev_get_bus_queue(self):
        q = Queue(loop=self.loop)
        for t in self.dev_knx_address_range():
            q.put_nowait(t)
        return q

    def add_target(self, target):
        self.q.put_nowait(target)

    @asyncio.coroutine
    def knx_bus_worker(self, transport, protocol, future, queue):
        """A worker for communicating with devices on the bus."""
        # TODO: before we scan the bus, make sure the gateway supports tunneling/routing services
        try:
            while True:
                target = queue.get_nowait()

                LOGGER.info('BUS: target: {}'.format(target))

                if not protocol.tunnel_established:
                    LOGGER.error('Tunnel is not open!')
                    return

                # tunnel_request = libknx.KnxTunnellingRequest(
                #     sockname=transport.get_extra_info('sockname'),
                #     communication_channel=protocol.communication_channel,
                #     sequence_count=protocol.sequence_count)
                # tunnel_request.set_knx_destination(target)
                # tunnel_request.pack_knx_message()
                # transport.sendto(tunnel_request.get_message())

                LOGGER.info('sending connect request')


                # connect_request = libknx.KnxConnectRequest(sockname=transport.get_extra_info('sockname'))
                # connect_request.pack_knx_message()
                # transport.sendto(connect_request.get_message())


                queue.task_done()
                yield from asyncio.sleep(2)

        except asyncio.CancelledError:
            pass
        except asyncio.QueueEmpty:
            pass


    @asyncio.coroutine
    def knx_search_worker(self):
        """Send a KnxDescription request to see if target is a KNX device."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, struct.pack('256s', str.encode(self.iface)))

            protocol = libknx.KnxGatewaySearch()
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
                        supported_services=[
                            libknx.KNX_SERVICES[k] for k, v in
                            response.body.get('dib_supp_sv_families').get('families').items()],
                        bus_devices=[])

                    self.knx_gateways.append(t)
        except asyncio.CancelledError:
            pass


    @asyncio.coroutine
    def knx_description_worker(self):
        """Send a KnxDescription request to see if target is a KNX device."""
        try:
            while True:
                target = self.q.get_nowait()
                LOGGER.debug('Scanning {}'.format(target))
                future = asyncio.Future()
                description = libknx.KnxGatewayDescription(future)
                transport, protocol = yield from self.loop.create_datagram_endpoint(
                    lambda: description,
                    remote_addr=(target[0], target[1]))

                response = yield from future

                if response:
                    self.alive_targets.add(target)

                    t = KnxTargetReport(
                        host=target[0],
                        port=target[1],
                        mac_address=response.body.get('dib_dev_info').get('knx_mac_address'),
                        knx_address=response.body.get('dib_dev_info').get('knx_address'),
                        device_serial=response.body.get('dib_dev_info').get('knx_device_serial'),
                        friendly_name=response.body.get('dib_dev_info').get('device_friendly_name'),
                        device_status=response.body.get('dib_dev_info').get('device_status'),
                        supported_services=[
                            libknx.KNX_SERVICES[k] for k,v in
                            response.body.get('dib_supp_sv_families').get('families').items()],
                        bus_devices=[])

                    self.knx_gateways.append(t)

                self.q.task_done()
        except asyncio.CancelledError:
            pass
        except asyncio.QueueEmpty:
            pass


    def print_knx_target(self, knx_target):
        """Print a target of type KnxTargetReport in a well formatted way."""
        # TODO: make this better, and prettier.
        out = {}
        out[knx_target.host] = collections.OrderedDict()
        o = out[knx_target.host]

        o['Port'] = knx_target.port
        o['MAC Address'] = knx_target.mac_address
        o['KNX Bus Address'] = knx_target.knx_address
        o['KNX Device Serial'] = knx_target.device_serial
        o['Device Friendly Name'] = binascii.b2a_qp(knx_target.friendly_name.strip())
        o['Device Status'] = knx_target.device_status
        o['Supported Services'] = knx_target.supported_services
        o['Bus Devices'] = knx_target.bus_devices

        print()

        def pretty(d, indent=0):
            for key, value in d.items():
                if indent is 0:
                    print('   ' * indent + str(key))
                else:
                    print('   ' * indent + str(key) + ': ', end="", flush=True)
                if isinstance(value, list):
                    for i,v in enumerate(value):
                        if i is 0:
                            print()
                        print('   ' * (indent+1) + str(v))
                elif isinstance(value, dict):
                    pretty(value, indent + 1)
                else:
                    print(value)

            print()

        pretty(out)


    @asyncio.coroutine
    def scan(self, search_mode=False, search_timeout=5, iface=None, bus_mode=False, monitor_mode=False):
        """The function that will be called by run_until_complete(). This is the main coroutine."""
        if search_mode:
            self.iface = iface
            self.search_timeout = search_timeout
            yield from self.search_gateways()

            for t in self.knx_gateways:
                self.print_knx_target(t)

            print('\nSearching done')

        elif monitor_mode:
            LOGGER.info('Starting bus monitor')
            future = asyncio.Future()
            bus_con = libknx.KnxBusMonitor(future)
            # TODO: is there a cleaner solution?
            global bus_protocol
            transport, bus_protocol = yield from self.loop.create_datagram_endpoint(
                lambda: bus_con,
                # remote_addr=(target[0], target[1]))
                remote_addr=('192.168.178.11', 3671))

            yield from future

            LOGGER.info('Stopping bus monitor')

        elif bus_mode and (1 is 2):
            # target = yield from self.gateway_queue.get()
            future = asyncio.Future()
            bus_con = libknx.KnxTunnelConnection(future)
            transport, protocol = yield from self.loop.create_datagram_endpoint(
                lambda: bus_con,
                # remote_addr=(target[0], target[1]))
                remote_addr=('192.168.178.11', 3671))

            # make sure the tunnel has been established
            connected = yield from future

            if connected:
                workers = [asyncio.Task(self.knx_bus_worker(transport, protocol, future), loop=self.loop)
                           for _ in range(self.max_workers if len(self.targets) > self.max_workers else 1)]

                self.t0 = time.time()
                LOGGER.info('Wait for bus workers')
                yield from self.bus_queue.join()
                self.t1 = time.time()
                for w in workers:
                    w.cancel()

                yield from asyncio.sleep(10)
                protocol.tunnel_disconnect()

            LOGGER.info('Done with bus scan!')

        else:
            workers = [asyncio.Task(self.knx_description_worker(), loop=self.loop)
                       for _ in range(self.max_workers if len(self.targets) > self.max_workers else len(self.targets))]
            self.t0 = time.time()
            yield from self.q.join()
            self.t1 = time.time()
            for w in workers:
                w.cancel()

            for t in self.knx_gateways:
                self.print_knx_target(t)

            print('\nScan took {} seconds'.format(self.t1 - self.t0))

            if bus_mode and self.knx_gateways:
                print('\nStarting bus scanning on {} KNXnet/IP gateways'.format(len(self.knx_gateways)))
                bus_scanners = [asyncio.Task(self.bus_scan(g), loop=self.loop) for g in self.knx_gateways]
                yield from asyncio.wait(bus_scanners)



    @asyncio.coroutine
    def search_gateways(self):
        self.t0 = time.time()
        yield from asyncio.ensure_future(asyncio.Task(self.knx_search_worker(), loop=self.loop))
        self.t1 = time.time()

        print('\nScan took {} seconds'.format(self.t1-self.t0))


    @asyncio.coroutine
    def bus_scan(self, knx_gateway):
        print('Starting bus scan on {}'.format(knx_gateway.host))
        queue = self.dev_get_bus_queue()
        future = asyncio.Future()
        bus_con = libknx.KnxTunnelConnection(future)
        transport, protocol = yield from self.loop.create_datagram_endpoint(
            lambda: bus_con, remote_addr=(knx_gateway.host, knx_gateway.port))

        # make sure the tunnel has been established
        connected = yield from future

        if connected:
            workers = [asyncio.Task(self.knx_bus_worker(transport, protocol, future, queue), loop=self.loop)
                       for _ in range(self.max_workers if len(self.targets) > self.max_workers else 1)]

            workers = [asyncio.Task(self.knx_bus_worker(transport, protocol, future, queue), loop=self.loop)]

            self.t0 = time.time()
            LOGGER.info('Wait for {} bus workers'.format(len(workers)))
            yield from queue.join()
            self.t1 = time.time()
            for w in workers:
                w.cancel()

            yield from asyncio.sleep(2)
            protocol.tunnel_disconnect()

        LOGGER.info('Done scanning bus on {}'.format(knx_gateway.host))


class Targets():
    """A helper class that expands provided target definitions to a proper list."""

    def __init__(self, targets=set(), ports=None):
        self.targets = set()
        self.ports = set()

        if ports:
            if isinstance(ports, list):
                for p in ports:
                    self.ports.add(p)
            else:
                self.ports.add(ports)

        if MOD_IPADDRESS:
            self._parse_ipaddress(targets)
        else:
            LOGGER.error('ipaddress module is not available! CIDR notifications will be ignored.')
            self._parse(targets)

    def _parse_ipaddress(self, targets):
        """Parse all targets with ipaddress module (with CIDR notation support)."""
        for target in targets:
            try:
                _targets = ipaddress.ip_network(target, strict=False)
            except ValueError:
                LOGGER.error('Invalid target definition, ignoring it: {}'.format(target))
                continue

            if '/' in target:
                _targets = _targets.hosts()

            for _target in _targets:
                for port in self.ports:
                    self.targets.add((str(_target), port))

    def _parse(self, targets):
        """Parse targets without ipaddress module. This provides a simple interface
        that does not add the ipaddress module as dependency."""
        for target in targets:
            try:
                socket.inet_aton(target)
            except socket.error:
                LOGGER.error('Invalid target definition, ignoring it: {}'.format(target))
                continue

            for port in self.ports:
                self.targets.add((target, port))


def main():
    args = ARGS.parse_args()
    if not args.targets and not args.search_mode:
        ARGS.print_help()
        return 1

    targets = Targets(args.targets, args.port)
    levels = [logging.ERROR, logging.WARN, logging.INFO, logging.DEBUG]
    if args.level > 2:
        format = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s'
    else:
        format = '%(message)s'
    logging.basicConfig(level=levels[min(args.level, len(levels)-1)], format=format)

    loop = asyncio.get_event_loop()

    if args.search_mode:
        if args.iface:
            if os.geteuid() != 0:
                LOGGER.error('-i/--interface option requires superuser privileges')
                sys.exit(1)
        else:
            LOGGER.error('--search option requires -i/--interface argument')
            sys.exit(1)
    else:
        LOGGER.info('Scanning {} target(s)'.format(len(targets.targets)))

    scanner = KnxScanner(targets=targets.targets, max_workers=args.workers)

    try:
        loop.run_until_complete(scanner.scan(
            search_mode=args.search_mode,
            search_timeout=args.search_timeout,
            bus_mode=args.bus_mode,
            monitor_mode=args.monitor_mode,
            iface=args.iface))
    except KeyboardInterrupt:
        for t in asyncio.Task.all_tasks():
            t.cancel()
        loop.run_forever()

        if args.monitor_mode and bus_protocol:
            # Make sure to send a DISCONNECT_REQUEST when the bus monitor will be closed
            bus_protocol.tunnel_disconnect()
    finally:
        loop.close()


if __name__ == '__main__':
    sys.exit(main())
