#!/usr/bin/env python3
import sys
import os
import argparse
import logging
import ipaddress

import libknx

# asyncio requires at least Python 3.3
if sys.version_info.major < 3 or \
    (sys.version_info.major > 2 and
    sys.version_info.minor < 3):
    print('At least Python version 3.3 is required to run this script!')
    sys.exit(1)
try:
    # Python 3.4 ships with asyncio in the standard libraries. Users of Python 3.3
    # need to install it, e.g.: pip install asyncio
    import asyncio
except ImportError:
    print('Please install the asyncio module!')
    sys.exit(1)

LOGGER = logging.getLogger(__name__)

# TODO: create proper arguments
# TODO: add subcommands for scanning modes?
ARGS = argparse.ArgumentParser(description="KNXnet/IP Scanner")
ARGS.add_argument(
    'targets', nargs='*',
    default=[], help='Target hostnames/IP addresses')
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
    '--bus-targets', action='store', dest='bus_targets',
    default=None, help='Bus target range')
ARGS.add_argument(
    '--bus-monitor', action='store_true', dest='bus_monitor_mode',
    default=False, help='Monitor all bus messages via KNXnet/IP gateway')
ARGS.add_argument(
    '--group-monitor', action='store_true', dest='group_monitor_mode',
    default=False, help='Monitor group bus messages via KNXnet/IP gateway')
ARGS.add_argument(
    '-v', '--verbose', action='count', dest='level',
    default=2, help='Verbose logging (repeat for more verbose)')
ARGS.add_argument(
    '-q', '--quiet', action='store_const', const=0, dest='level',
    default=2, help='Only log errors')


class Targets:
    """A helper class that expands provided target definitions to a list of tuples."""
    def __init__(self, targets=set(), ports=3671):
        self.targets = set()
        self.ports = set()
        if isinstance(ports, list):
            for p in ports:
                self.ports.add(p)
        elif isinstance(ports, int):
            self.ports.add(ports)
        else:
            self.ports.add(3671)

        if isinstance(targets, set) or \
            isinstance(targets, list):
            self._parse(targets)

    def _parse(self, targets):
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


class KnxTargets:
    """A helper class that expands knx bus targets to lists."""
    def __init__(self, targets):
        if not targets:
            self.targets = set()
        else:
            assert isinstance(targets, str)
            assert '-' in targets
            assert targets.count('-') < 2
            # TODO: also parse dashes in octets
            try:
                f, t = targets.split('-')
            except ValueError:
                return
            if not self.is_valid_physical_address(f) or \
                not self.is_valid_physical_address(t):
                return
            # TODO: make it group address aware
            # TODO: make sure t is higher than f
            self.targets = self.expand_targets(f, t)

    @staticmethod
    def expand_targets(f, t):
        targets = set()
        for i in range(int(f.split('.')[0]),
                       int(t.split('.')[0]) if int(t.split('.')[0]) > int(f.split('.')[0]) else (int(t.split('.')[0]) + 1)):
            for j in range(int(f.split('.')[1]),
                           int(t.split('.')[1]) if int(t.split('.')[1]) > int(f.split('.')[1]) else (int(t.split('.')[1]) + 1)):
                for g in range(int(f.split('.')[2]),
                               int(t.split('.')[2]) if int(t.split('.')[2]) > int(f.split('.')[2]) else (int(t.split('.')[2]) + 1)):
                    targets.add('{}.{}.{}'.format(i, j, g))
        return targets

    @staticmethod
    def is_valid_physical_address(address):
        assert isinstance(address, str)
        try:
            parts = [int(i) for i in address.split('.')]
        except ValueError:
            return False
        if len(parts) is not 3:
            return False
        if (parts[0] < 1 or parts[0] > 15) or (parts[1] < 0 or parts[1] > 15):
            return False
        if parts[2] < 0 or parts[2] > 255:
            return False
        return True

    @staticmethod
    def is_valid_group_address(address):
        assert isinstance(address, str)
        try:
            parts = [int(i) for i in address.split('/')]
        except ValueError:
            return False
        if len(parts) < 2 or len(parts) > 3:
            return False
        if (parts[0] < 0 or parts[0] > 15) or (parts[1] < 0 or parts[1] > 15):
            return False
        if len(parts) is 3:
            if parts[2] < 0 or parts[2] > 255:
                return False
        return True


def main():
    args = ARGS.parse_args()
    if not args.targets and not args.search_mode:
        ARGS.print_help()
        sys.exit()

    targets = Targets(args.targets, args.port)
    bus_targets = KnxTargets(args.bus_targets)
    levels = [logging.ERROR, logging.WARN, logging.INFO, logging.DEBUG]
    format = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s' if args.level > 2 else '%(message)s'
    logging.basicConfig(level=levels[min(args.level, len(levels)-1)], format=format)
    loop = asyncio.get_event_loop()

    if args.search_mode:
        if not args.iface:
            LOGGER.error('--search option requires -i/--interface argument')
            sys.exit(1)

        if os.geteuid() != 0:
            LOGGER.error('-i/--interface option requires superuser privileges')
            sys.exit(1)
    else:
        LOGGER.info('Scanning {} target(s)'.format(len(targets.targets)))

    scanner = libknx.KnxScanner(targets=targets.targets, max_workers=args.workers)

    try:
        loop.run_until_complete(scanner.scan(
            search_mode=args.search_mode,
            search_timeout=args.search_timeout,
            bus_mode=args.bus_mode,
            bus_targets=bus_targets,
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
    main()
