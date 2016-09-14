#!/usr/bin/env python3
import sys
import os
import argparse
import logging

from libknxmap import KnxMap, Targets, KnxTargets

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
ARGS = argparse.ArgumentParser(
    description='KNXnet/IP network and bus mapper',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
SUBARGS = ARGS.add_subparsers(dest='cmd')

# General options
ARGS.add_argument(
    '-v', '--verbose', action='count', dest='level',
    default=2, help='Verbose logging (repeat for more verbose)')
ARGS.add_argument(
    '-q', '--quiet', action='store_const', const=0, dest='level',
    default=2, help='Only log errors')
ARGS.add_argument(
    '-p', action='store', dest='port', type=int,
    default=3671, help='UDP port to be scanned')
ARGS.add_argument(
    '-i', action='store', dest='iface',
    default=None, help='Interface to be used')
ARGS.add_argument(
    '--workers', action='store', type=int, metavar='N',
    default=30, help='Limit concurrent workers')
ARGS.add_argument(
    '--timeout', action='store', dest='timeout', type=int,
    default=2, help='Timeout in seconds for unicast description responses')
ARGS.add_argument(
    '--retries', action='store', dest='retries', type=int,
    default=3, help='Count of retries for description requests')

pscan = SUBARGS.add_parser('scan', help='Scan KNXnet/IP gateways and attached bus devices')
pscan.add_argument(
    'targets', help='KNXnet/IP gateway', metavar='gateway')
pscan.add_argument(
    'bus_targets', action='store', nargs='?',
    default=None, help='Bus target range (e.g. 1.1.0-1.1.10)')
pscan.add_argument(
    '--bus-info', action='store_true', dest='bus_info',
    default=False, help='Try to extract information from alive bus devices')
pscan.add_argument(
    '--key', action='store', dest='auth_key',
    default=0xffffffff, help='Authorize key for System 2 and System 7 devices')

psearch = SUBARGS.add_parser('search',
                             help='Search for KNXnet/IP gateways on the local network')
psearch.add_argument(
    '--search-timeout', action='store', dest='search_timeout', type=int,
    default=5, help='Timeout in seconds for multicast responses')

pwrite = SUBARGS.add_parser('write', help='Write a value to a group address')
pwrite.add_argument(
    'targets', help='KNXnet/IP gateway', metavar='gateway')
pwrite.add_argument(
    'group_write_address', help='A KNX group address to write to')
pwrite.add_argument(
    'group_write_value', default=0, help='Value to write to the group address')
pwrite.add_argument(
    '--routing', action='store_true', dest='routing',
    default=False, help='Use Routing instead of Tunnelling')

papci = SUBARGS.add_parser('apci', help='Execute an APCI function')
papci.add_argument(
    'targets', help='KNXnet/IP gateway', metavar='gateway')
papci.add_argument(
    'device', help='An individual KNX address')
papci.add_argument(
    'apci_type', default=0, help='APCI type')
papci.add_argument(
    '--routing', action='store_true', dest='routing',
    default=False, help='Use Routing instead of Tunnelling')
papci.add_argument(
    '--memory-address', action='store', dest='memory_address',
    default=0x0060, help='Memory address')
papci.add_argument(
    '--read-count', action='store_true', dest='read_count',
    default=1, help='Number of bytes to read from memory')
papci.add_argument(
    '--object-index', action='store', dest='object_index',
    default=0, help='TBD')
papci.add_argument(
    '--property-id', action='store', dest='property_id',
    default=0x0f, help='TBD')
papci.add_argument(
    '--elements', action='store', dest='num_elements',
    default=1, help='TBD')
papci.add_argument(
    '--start-index', action='store', dest='start_index',
    default=1, help='TBD')
papci.add_argument(
    '--key', action='store', dest='auth_key',
    default=0xffffffff, help='Authorize key for System 2 and System 7 devices')

pbrute = SUBARGS.add_parser('brute', help='Bruteforce authentication key')
pbrute.add_argument(
    'targets', help='KNXnet/IP gateway', metavar='gateway')
pbrute.add_argument(
    'bus_target', help='Individual address of bus device')

pmonitor = SUBARGS.add_parser('monitor', help='Monitor bus and group messages')
pmonitor.add_argument(
    'targets', help='KNXnet/IP gateway', metavar='gateway')
pmonitor.add_argument(
    '--group-monitor', action='store_true', dest='group_monitor_mode',
    default=False, help='Monitor group instead of messages via KNXnet/IP gateway')


def main():
    args = ARGS.parse_args()
    levels = [logging.ERROR, logging.WARN, logging.INFO, logging.DEBUG]
    format = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s' if args.level > 2 else '%(message)s'
    logging.basicConfig(level=levels[min(args.level, len(levels) - 1)], format=format)
    loop = asyncio.get_event_loop()

    if hasattr(args, 'targets'):
        targets = Targets(args.targets, args.port)
        knxmap = KnxMap(targets=targets.targets, max_workers=args.workers)
    else:
        knxmap = KnxMap(max_workers=args.workers)

    try:
        if args.cmd == 'search':
            if not args.iface:
                LOGGER.error('--search option requires -i/--interface argument')
                sys.exit(1)
            if os.geteuid() != 0:
                LOGGER.error('-i/--interface option requires superuser privileges')
                sys.exit(1)
            loop.run_until_complete(knxmap.search(
                search_timeout=args.search_timeout,
                iface=args.iface))
        elif args.cmd == 'apci':
            loop.run_until_complete(knxmap.apci(
                target=args.device,
                desc_timeout=args.timeout,
                desc_retries=args.retries,
                iface=args.iface,
                args=args))
        elif args.cmd == 'write':
            loop.run_until_complete(knxmap.group_writer(
                target=args.group_write_address,
                value=args.group_write_value,
                routing=args.routing,
                desc_timeout=args.timeout,
                desc_retries=args.retries,
                iface=args.iface))
        elif args.cmd == 'monitor':
            loop.run_until_complete(knxmap.monitor(
                group_monitor_mode=args.group_monitor_mode))
        elif args.cmd == 'brute':
            loop.run_until_complete(knxmap.brute(
                bus_target=KnxTargets(args.bus_target)))
        elif args.cmd == 'scan':
            LOGGER.info('Scanning {} target(s)'.format(len(targets.targets)))
            bus_targets = KnxTargets(args.bus_targets)
            loop.run_until_complete(knxmap.scan(
                desc_timeout=args.timeout,
                desc_retries=args.retries,
                bus_targets=bus_targets.targets,
                bus_info=args.bus_info,
                auth_key=args.auth_key))
    except KeyboardInterrupt:
        for t in asyncio.Task.all_tasks():
            t.cancel()
        loop.run_forever()

        if knxmap.bus_protocols:
            # Make sure to send a DISCONNECT_REQUEST
            # when the bus monitor will be closed.
            for p in knxmap.bus_protocols:
                p.knx_tunnel_disconnect()
    finally:
        loop.close()


if __name__ == '__main__':
    main()
