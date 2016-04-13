#! /usr/bin/env python3
import time
import sys
import argparse
import logging
import socket

import libknx

# asyncio requires at least Python 3.3
if sys.version_info.major < 3 or \
    (sys.version_info.major > 2 and \
    sys.version_info.minor < 3):
    print('At least Python version 3.3 is required to run this script!')
    sys.exit(1)

# Python 3.4 ships with asyncio in the standard libraries. Users with Python 3.3
# need to install it, e.g.: pip install asyncio
try:
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
    '-p', '--port', action='store_const', const=3671, dest='port',
    default=3671, help='UDP port to be scanned')
ARGS.add_argument(
    '-sG', '--search', action='store_true', dest='search',
    default=False, help='Find local KNX gateways via search requests')


class KnxDescription(asyncio.DatagramProtocol):
    # TODO: will be moved into libknx

    def __init__(self, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.response = None

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')

        # initialize desciption request
        packet = libknx.messages.KnxDescriptionRequest(sockname=self.sockname)
        packet.pack_knx_message()

        self.transport.sendto(packet.get_message())
        LOGGER.debug('KnxDescriptionRequest sent')

    def datagram_received(self, data, addr):
        try:
            LOGGER.debug('Parsing KnxDescriptionResponse')
            self.response = libknx.messages.KnxDescriptionResponse(data)

            if self.response:
                LOGGER.debug("Got valid description request back!")
            else:
                LOGGER.info('Not a valid description response!')
        except Exception as e:
            LOGGER.exception(e)

        self.transport.close()


class KnxSearch(asyncio.DatagramProtocol):
    # TODO: will be moved into libknx

    def __init__(self, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.responses = set()

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')

        # initialize desciption request
        packet = libknx.messages.KnxSearchRequest(sockname=self.sockname)
        packet.pack_knx_message()

        LOGGER.debug('Sending KnxSearchRequest')
        #self.transport.sendto(packet.get_message(), addr=None)
        # TODO: is this a asyncio bug? need to send it on the socket object
        self.transport.get_extra_info('socket').send(packet.get_message())
        LOGGER.debug('KnxSearchRequest sent')

    def datagram_received(self, data, addr):
        try:
            LOGGER.debug('Parsing KnxSearchResponse')
            response = libknx.messages.KnxSearchResponse(data)

            if response:
                LOGGER.debug("Got valid searcg request back!")
                self.responses.add(response)
            else:
                LOGGER.info('Not a valid search response!')
        except Exception as e:
            LOGGER.exception(e)


class KnxScanner():
    """The main scanner instance that takes care of scheduling scans for the targets."""

    def __init__(self, targets=set(), max_tasks=10, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.max_tasks = max_tasks
        # the Queue contains all targets
        self.q = Queue(loop=self.loop)
        self.gateway_queue = Queue(loop=self.loop)
        self.bus_queue = Queue(loop=self.loop)

        self.targets = targets
        self.alive_targets = set()
        self.knx_gateways = set()

        for target in targets:
            self.add_target(target)

        # save some timing information
        self.t0 = time.time()
        self.t1 = None


    def add_target(self, target):
        self.q.put_nowait(target)


    @asyncio.coroutine
    def knx_bus_worker(self):
        """A worker for communicating with devices on the bus."""
        pass


    @asyncio.coroutine
    def knx_search_worker(self):
        """Send a KnxDescription request to see if target is a KNX device."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.connect(('224.0.23.12', 3671))

        try:
            transport, protocol = yield from self.loop.create_datagram_endpoint(
                KnxSearch,
                local_addr=None,
                remote_addr=None,
                sock=sock)

            yield from asyncio.sleep(5)

            if protocol.responses:
                # we found some KNX gateways
                for r in protocol.responses:
                    LOGGER.info('KNX gateway: {}'.format(r))
                    self.alive_targets.add(r)
                    self.knx_gateways.add(r)
        except asyncio.CancelledError:
            pass


    # @asyncio.coroutine
    # def knx_find_bus_devices(self, target):
    #     """Find devices on the bus accessible via target (which should be a KNX gateway)."""
    #     transport, protocol = yield from self.loop.create_datagram_endpoint(
    #         lambda: KnxConnection(),
    #         remote_addr=(target, KNX_UDP_PORT)
    #     )
    #
    #     yield from protocol.data_received()
    #
    #     while not transport.is_closing:
    #         print('waiting...')
    #         asyncio.sleep(2)
    #
    #     print(dir(transport))


    @asyncio.coroutine
    def knx_description_worker(self):
        """Send a KnxDescription request to see if target is a KNX device."""
        try:
            while True:
                target = yield from self.q.get()
                transport, protocol = yield from self.loop.create_datagram_endpoint(
                    KnxDescription,
                    remote_addr=(target[0], target[1]))

                yield from asyncio.sleep(2)

                if protocol.response:
                    # we have a valid KNX gateway
                    LOGGER.info('KNX gateway: {}'.format(target))
                    self.alive_targets.add(target)
                    self.knx_gateways.add(target)

                self.q.task_done()
        except asyncio.CancelledError:
            pass


    @asyncio.coroutine
    def scan(self, search=False):
        """The function that will be called by run_until_complete(). This is the main coroutine."""
        if search:
            yield from self.search_gateways()
        else:
            workers = [asyncio.Task(self.knx_description_worker(), loop=self.loop)
                       for _ in range(self.max_tasks if len(self.targets) > self.max_tasks else len(self.targets))]
            self.t0 = time.time()
            yield from self.q.join()
            self.t1 = time.time()
            for w in workers:
                w.cancel()


            print('\n\nFound {} device(s): {}'.format(len(self.alive_targets), self.alive_targets))
            print('Scan took {} seconds'.format(self.t1-self.t0))


    @asyncio.coroutine
    def search_gateways(self):
        self.t0 = time.time()
        yield from asyncio.ensure_future(asyncio.Task(self.knx_search_worker(), loop=self.loop))
        self.t1 = time.time()


        print('\n\nFound {} device(s): {}'.format(len(self.alive_targets), self.alive_targets))
        print('Scan took {} seconds'.format(self.t1-self.t0))


class Targets():
    """A helper class that expands provided targets to proper lists."""
    def __init__(self, targets=set(), ports=None):
        self.targets = set()
        self.ports = set()

        if ports:
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
    if not args.targets and not args.search:
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

    if args.search:
        scanner = KnxScanner(targets=targets.targets)
    else:
        scanner = KnxScanner(targets=targets.targets)
        LOGGER.info('Scanning {} target(s)'.format(len(targets.targets)))

    try:
        loop.run_until_complete(scanner.scan(search=True))
    except KeyboardInterrupt:
        for t in asyncio.Task.all_tasks():
            t.cancel()
        loop.run_forever()
    finally:
        loop.close()


if __name__ == '__main__':
    sys.exit(main())
