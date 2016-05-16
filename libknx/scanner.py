import asyncio
import argparse
import binascii
import collections
import logging
import os
import socket
import struct
import sys
import time
try:
    # Python 3.4
    from asyncio import JoinableQueue as Queue
except ImportError:
    # Python 3.5 renamed it to Queue
    from asyncio import Queue

from .core import *
from .messages import *
from .gateway import *
from .bus import *

__all__ = ['KnxScanner']

LOGGER = logging.getLogger(__name__)

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
    def __init__(self, targets=None, max_workers=100, loop=None, ):
        self.loop = loop or asyncio.get_event_loop()
        self.max_workers = max_workers
        # the Queue contains all targets
        self.q = Queue(loop=self.loop)

        self.gateway_queue = Queue(loop=self.loop)
        self.bus_queue = Queue(loop=self.loop)
        self.bus_protocol = None

        # DEV: add dev targets
        self.dev_add_knx_targets(
            self.dev_knx_address_range())

        if targets:
            self.targets = targets
        else:
            self.targets = set()
        self.alive_targets = set()
        self.knx_gateways = list()
        self.bus_devices = set()

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

        t = []
        for i in [1]:
            for ii in [1]:
                for iii in range(256):
                    t.append('{}.{}.{}'.format(i, ii, iii))

        return t

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
    def knx_bus_worker(self, transport, protocol, queue):
        """A worker for communicating with devices on the bus."""
        # TODO: before we scan the bus, make sure the gateway supports tunneling/routing services
        try:
            while True:
                target = queue.get_nowait()
                LOGGER.debug('BUS: target: {}'.format(target))
                if not protocol.tunnel_established:
                    LOGGER.error('Tunnel is not open!')
                    return

                target_future = asyncio.Future()
                protocol.target_futures[target] = target_future
                tunnel_request = KnxTunnellingRequest(
                    sockname=transport.get_extra_info('sockname'),
                    communication_channel=protocol.communication_channel,
                    sequence_count=protocol.sequence_count,
                    knx_source=protocol.knx_source_address,
                    knx_destination=target)
                transport.sendto(tunnel_request.get_message())
                if protocol.sequence_count == 255:
                    protocol.sequence_count = 0
                else:
                    protocol.sequence_count += 1

                alive = yield from target_future
                if alive:
                    self.bus_devices.add(target)

                queue.task_done()
        except asyncio.CancelledError:
            pass
        except asyncio.QueueEmpty:
            pass

    @asyncio.coroutine
    def bus_scan(self, knx_gateway):
        queue = self.dev_get_bus_queue()
        future = asyncio.Future()
        bus_con = KnxTunnelConnection(future)
        transport, self.bus_protocol = yield from self.loop.create_datagram_endpoint(
            lambda: bus_con, remote_addr=(knx_gateway.host, knx_gateway.port))

        # make sure the tunnel has been established
        connected = yield from future
        if connected:
            workers = [asyncio.Task(self.knx_bus_worker(transport, self.bus_protocol, queue), loop=self.loop)]
            self.t0 = time.time()
            yield from queue.join()
            self.t1 = time.time()
            for w in workers:
                w.cancel()
            self.bus_protocol.knx_tunnel_disconnect()

        LOGGER.info('Bus scan took {} seconds'.format(self.t1 - self.t0))

        if self.bus_devices:
            LOGGER.info('Found {} physical addresses'.format(len(self.bus_devices)))
            LOGGER.info(self.bus_devices)

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
                future = asyncio.Future()
                description = KnxGatewayDescription(future)
                yield from self.loop.create_datagram_endpoint(
                    lambda: description,
                    remote_addr=target)
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
                            KNX_SERVICES[k] for k,v in
                            response.body.get('dib_supp_sv_families').get('families').items()],
                        bus_devices=[])

                    self.knx_gateways.append(t)
                self.q.task_done()
        except asyncio.CancelledError:
            pass
        except asyncio.QueueEmpty:
            pass

    @asyncio.coroutine
    def scan(self, search_mode=False, search_timeout=5, iface=None,
             bus_mode=False, bus_monitor_mode=False, group_monitor_mode=False):
        """The function that will be called by run_until_complete(). This is the main coroutine."""
        if search_mode:
            self.iface = iface
            self.search_timeout = search_timeout
            yield from self.search_gateways()
            for t in self.knx_gateways:
                self.print_knx_target(t)

            LOGGER.info('Searching done')

        elif bus_monitor_mode or group_monitor_mode:
            LOGGER.info('Starting bus monitor')
            future = asyncio.Future()
            bus_con = KnxBusMonitor(future, group_monitor=group_monitor_mode)
            transport, self.bus_protocol = yield from self.loop.create_datagram_endpoint(
                lambda: bus_con,
                remote_addr=list(self.targets)[0])
            yield from future

            LOGGER.info('Stopping bus monitor')

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

            LOGGER.info('Scan took {} seconds'.format(self.t1 - self.t0))
            if bus_mode and self.knx_gateways:
                bus_scanners = [asyncio.Task(self.bus_scan(g), loop=self.loop) for g in self.knx_gateways]
                yield from asyncio.wait(bus_scanners)

    @staticmethod
    def print_knx_target(knx_target):
        """Print a target of type KnxTargetReport in a well formatted way."""
        # TODO: make this better, and prettier.
        out = dict()
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
                    for i, v in enumerate(value):
                        if i is 0:
                            print()
                        print('   ' * (indent + 1) + str(v))
                elif isinstance(value, dict):
                    pretty(value, indent + 1)
                else:
                    print(value)
            print()

        pretty(out)
