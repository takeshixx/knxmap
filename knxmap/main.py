#!/usr/bin/env python3
import sys
import os
import argparse
import logging
import functools

from knxmap import KnxMap, Targets, KnxTargets
from knxmap.misc import setup_logger

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
    default=2, help='verbose logging (repeat for more verbosity)')
ARGS.add_argument(
    '-q', '--quiet', action='store_const', const=0, dest='level',
    default=2, help='only log errors')
ARGS.add_argument(
    '-t', '--trace', action='store_const', const=9, dest='level',
    default=9, help='print all packets/messages')
ARGS.add_argument(
    '-p', action='store', dest='port', type=int,
    default=3671, help='target UDP port')
ARGS.add_argument(
    '-i', action='store', dest='iface',
    default=None, help='network interface')
ARGS.add_argument(
    '--workers', action='store', type=int, metavar='N',
    default=30, help='count of concurrent workers')
ARGS.add_argument(
    '--connections', action='store', type=int, metavar='N', default=1,
    help='count of concurrent tunnel connections (0 means as much as a device supports)')
ARGS.add_argument(
    '--timeout', action='store', dest='timeout', type=int,
    default=2, help='timeout (in seconds) for unicast description responses')
ARGS.add_argument(
    '--retries', action='store', dest='retries', type=int,
    default=3, help='count of retries for description requests')
ARGS.add_argument(
    '--knx-source-address', action='store', dest='knx_source',
    default=None, help='KNX source address used for messages to bus devices')
ARGS.add_argument(
    '--medium', action='store', default='net',
    help='authorization key for System 2 and System 7 devices')
ARGS.add_argument(
    '--nat', action='store_true', dest='nat_mode',
    default=False, help='NAT mode')

pscan = SUBARGS.add_parser('scan', help='scan KNXnet/IP gateways and attached bus devices',
                           formatter_class=argparse.ArgumentDefaultsHelpFormatter)
pscan.add_argument(
    'targets', help='KNXnet/IP gateway IP address or hostname', metavar='gateway')
pscan.add_argument(
    'bus_targets', action='store', nargs='?',
    default=None, help='bus target range (e.g. 1.1.0-1.1.10)')
pscan.add_argument(
    '--omit-configuration-reads', action='store_false', dest='configuration_reads',
    default=True, help='omit DEVICE_CONFIGURATION_REQUESTs (scanning will be faster, but less verbose')
pscan.add_argument(
    '--bus-info', action='store_true', dest='bus_info',
    default=False, help='try to extract information from alive bus devices')
pscan.add_argument(
    '--key', action='store', dest='auth_key',
    default=0xffffffff, help='authorization key for System 2 and System 7 devices')
pscan.add_argument(
    '--bus-timeout', action='store', dest='bus_timeout', type=int,
    default=2, help='waiting time (in seconds) for deferred NDP messages')
pscan.add_argument(
    '--ignore-auth', action='store_true', dest='ignore_auth',
    default=False, help='ignore authorization')

psearch = SUBARGS.add_parser('search',
                             help='search for KNXnet/IP gateways on the local network')
ARGS.add_argument(
    '--multicast', action='store', dest='multicast_addr',
    default='224.0.23.12', help='multicast address for search requests')
psearch.add_argument(
    '--search-timeout', action='store', dest='search_timeout', type=int,
    default=5, help='timeout (in seconds) for multicast responses')

pwrite = SUBARGS.add_parser('write', help='Write a value to a group address',
                            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
pwrite.add_argument(
    'targets', help='KNXnet/IP gateway IP address or hostname', metavar='gateway')
pwrite.add_argument(
    'group_write_address', help='a KNX group address to write values to')
pwrite.add_argument(
    'group_write_value', default=0, help='value to write to a group address')
pwrite.add_argument(
    '--routing', action='store_true', dest='routing',
    default=False, help='use Routing instead of Tunnelling')

papci = SUBARGS.add_parser('apci', help='Execute an APCI function',
                           formatter_class=argparse.ArgumentDefaultsHelpFormatter)
papci.add_argument(
    'targets', help='KNXnet/IP gateway IP address or hostname', metavar='gateway')
papci.add_argument(
    'device', help='an individual (physical) KNX address')
papci.add_argument(
    'apci_type', default=0, help='APCI type')
papci.add_argument(
    '--routing', action='store_true', dest='routing',
    default=False, help='use Routing instead of Tunnelling')
papci.add_argument(
    '--memory-address', action='store', dest='memory_address',
    default=0x0060, help='target memory address')
papci.add_argument(
    '--read-count', action='store', dest='read_count', type=int,
    default=1, help='count of bytes to read from memory')
papci.add_argument(
    '--object-index', action='store', dest='object_index',
    type=int, default=0, help='TBD')
papci.add_argument(
    '--property-id', action='store', dest='property_id',
    default=0x0f, help='TBD')
papci.add_argument(
    '--elements', action='store', dest='num_elements',
    type=int, default=1, help='TBD')
papci.add_argument(
    '--start-index', action='store', dest='start_index',
    type=int, default=1, help='TBD')
papci.add_argument(
    '--key', action='store', dest='auth_key',
    default=0xffffffff, help='authorization key for System 2 and System 7 devices')
papci.add_argument(
    '--new-key', action='store', dest='new_auth_key',
    default=0xffffffff, help='new authorization key')
papci.add_argument(
    '--key-level', action='store', dest='auth_level', type=int,
    default=0, help='authorization level for A_Key_Write')
papci.add_argument(
    '--memory-data', action='store', dest='memory_data',
    default=0x00, help='data to be written to a memory address')
papci.add_argument(
    '--toggle', action='store_true', dest='toggle',
    default=False, help='toggle something (e.g. progmode)')
papci.add_argument(
    '--ignore-auth', action='store_true', dest='ignore_auth',
    default=False, help='ignore authorization')

pbrute = SUBARGS.add_parser('brute', help='Bruteforce authentication key',
                            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
pbrute.add_argument(
    'targets', help='KNXnet/IP gateway IP address or hostname', metavar='gateway')
pbrute.add_argument(
    'bus_target', help='individual address of a bus device')
pbrute.add_argument(
    '--full-key-space', action='store_true', dest='full_key_space',
    default=False, help='bruteforce the full key space (0 - 0xffffffff)')

pmonitor = SUBARGS.add_parser('monitor', help='Monitor bus and group messages',
                              formatter_class=argparse.ArgumentDefaultsHelpFormatter)
pmonitor.add_argument(
    'targets', help='KNXnet/IP gateway IP address or hostname', metavar='gateway')
pmonitor.add_argument(
    '--group-monitor', action='store_true', dest='group_monitor_mode',
    default=False, help='monitor group- instead of bus-messages via KNXnet/IP gateway')


def main():
    args = ARGS.parse_args()
    setup_logger(args.level)
    loop = asyncio.get_event_loop()

    if hasattr(args, 'targets'):
        targets = Targets(args.targets, args.port)
        knxmap = KnxMap(targets=targets.targets,
                        max_workers=args.workers,
                        max_connections=args.connections,
                        medium=args.medium,
                        nat_mode=args.nat_mode)
    else:
        knxmap = KnxMap(max_workers=args.workers,
                        max_connections=args.connections,
                        medium=args.medium,
                        nat_mode=args.nat_mode)
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
                iface=args.iface,
                multicast_addr=args.multicast_addr,
                port=args.port))
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
            bus_target = KnxTargets(args.bus_target)
            loop.run_until_complete(knxmap.brute(
                bus_target=bus_target.targets,
                full_key_space=args.full_key_space))
        elif args.cmd == 'scan':
            LOGGER.info('Scanning {} target(s)'.format(len(targets.targets)))
            bus_targets = KnxTargets(args.bus_targets)
            loop.run_until_complete(knxmap.scan(
                desc_timeout=args.timeout,
                desc_retries=args.retries,
                bus_timeout=args.bus_timeout,
                bus_targets=bus_targets.targets,
                bus_info=args.bus_info,
                knx_source=args.knx_source,
                auth_key=args.auth_key,
                ignore_auth=args.ignore_auth,
                configuration_reads=args.configuration_reads))
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
