#! /usr/bin/env python3
import argparse
import logging
import os
import socket
import sys

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
    default=30, help='Limit concurrent workers')
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
    '--bus-monitor', action='store_true', dest='bus_monitor_mode',
    default=False, help='Monitor all bus messages via KNXnet/IP gateway')
ARGS.add_argument(
    '--group-monitor', action='store_true', dest='group_monitor_mode',
    default=False, help='Monitor group bus messages via KNXnet/IP gateway')


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

    scanner = libknx.KnxScanner(targets=targets.targets, max_workers=args.workers)

    try:
        loop.run_until_complete(scanner.scan(
            search_mode=args.search_mode,
            search_timeout=args.search_timeout,
            bus_mode=args.bus_mode,
            bus_monitor_mode=args.bus_monitor_mode,
            group_monitor_mode=args.group_monitor_mode,
            iface=args.iface))
    except KeyboardInterrupt:
        for t in asyncio.Task.all_tasks():
            t.cancel()
        loop.run_forever()

        if scanner.bus_protocol:
            # Make sure to send a DISCONNECT_REQUEST when the bus monitor will be closed
            scanner.bus_protocol.knx_tunnel_disconnect()
    finally:
        loop.close()


if __name__ == '__main__':
    sys.exit(main())
