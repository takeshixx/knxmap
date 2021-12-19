import sys
import asyncio
import unittest

from knxmap.core import KnxMap
from knxmap.targets import Targets, KnxTargets
from knxmap.misc import setup_logger
from knxmap.exceptions import KnxTunnelException


class Args(object):
    """A wrapper class that will substitute the argparse
    object for test cases."""
    def __init__(self, apci_type=None, auth_key=0xffffffff,
                 ignore_auth=False, memory_address=None,
                 memory_data=0x00, new_auth_key=0xffffffff,
                 read_count=1, auth_level=0, object_index=0,
                 num_elements=1, start_index=0, toggle=False,
                 value=0, knx_source='0.0.0'):
        self.apci_type = apci_type
        self.auth_key = auth_key
        self.new_auth_key = new_auth_key
        self.auth_level = auth_level
        self.ignore_auth = ignore_auth
        self.memory_address = memory_address
        self.memory_data = memory_data
        self.read_count = read_count
        self.object_index = object_index
        self.num_elements = num_elements
        self.start_index = start_index
        self.toggle = toggle
        self.value = value
        self.knx_source = knx_source


class BasicTests(unittest.TestCase):
    TARGET = None

    def setUp(self):
        setup_logger(0)
        self.loop = asyncio.get_event_loop()
        self.targets = Targets(self.TARGET, ports=3671)
        self.workers = 30
        self.connections = 1
        self.medium = 'net'
        self.timeout = 2
        self.retries = 3
        self.bus_timeout = 2
        self.search_timeout = 5
        self.auth_key = 0xffffffff
        self.knxmap = KnxMap(targets=self.targets.targets,
                             max_workers=self.workers,
                             max_connections=self.connections,
                             medium=self.medium,
                             testing=True)

    def test_scan_gateway(self):
        try:
            self.loop.run_until_complete(self.knxmap.scan())
        except KnxTunnelException as e:
            self.fail(e.message)

    def test_scan_bus_device(self):
        bus_targets = KnxTargets('1.1.1')
        try:
            self.loop.run_until_complete(self.knxmap.scan(
                bus_targets=bus_targets.targets))
        except KnxTunnelException as e:
            self.fail(e.message)

    def test_scan_bus_device_verbose(self):
        bus_targets = KnxTargets('1.1.1')
        try:
            self.loop.run_until_complete(self.knxmap.scan(
                bus_targets=bus_targets.targets,
                bus_info=True,
                auth_key=self.auth_key))
        except KnxTunnelException as e:
            self.fail(e.message)

    def test_brute_default(self):
        bus_targets = KnxTargets('1.1.1')
        try:
            self.loop.run_until_complete(self.knxmap.brute(
                bus_target=bus_targets.targets,
                full_key_space=False,
                wordlist=None))
        except KnxTunnelException as e:
            self.fail(e.message)

    def test_apci_memory_read(self):
        args = Args(apci_type='Memory_Read',
                    memory_address=0x0116)
        try:
            self.loop.run_until_complete(self.knxmap.apci(
                target='1.1.2',
                args=args))
        except KnxTunnelException as e:
            self.fail(e.message)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        BasicTests.TARGET = sys.argv.pop()
    else:
        print('This test case requires a KNX gateway')
        sys.exit(1)
    unittest.main()
