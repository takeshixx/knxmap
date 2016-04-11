#! /usr/bin/env python2
import multiprocessing
import time
import sys
import subprocess
import socket

import struct

import libknx
import libknx.messages

import functools

import asyncio

try:
    # Python 3.4.
    from asyncio import JoinableQueue as Queue
except ImportError:
    # Python 3.5.
    from asyncio import Queue


KNX_UDP_PORT = 3671


class KnxConnection:

    def _log(self, msg):
        print('Peername: {}, Message: {}'.format(self.peername, msg))


    device_alive = False
    tunnel_established = False

    communication_channel = None


    def __init__(self, loop=None, port=55775):
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None


    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')

        self._log('Connection established')

        # TODO: start to check if system is alive
        #       use technique from NSE scripts.

        # initialize connection request
        packet = libknx.messages.KnxConnectionRequest(port=self.sockname[1])
        packet.set_source_ip(self.sockname[0])
        packet.pack_knx_message()

        print(packet.get_message())
        self.transport.sendto(packet.get_message())
        self._log('KnxConnectionRequest sent')


    def datagram_received(self, data, addr):
        self._log('Data received')
        self._log('data: {}'.format(data))

        # TODO: decide if device is alive


        try:
            # parse the KNX header to see what type of KNX message it is
            header = {}
            header['header_length'], \
            header['protocol_version'], \
            header['service_type'], \
            header['total_length'] = struct.unpack('>BBHH', data[:6])
            message_type = int(header['service_type'])
        except Exception as e:
            print(e)
            sys.exit(1)


        if message_type == 0x0202: # it's a search response
            # TODO: implement KnxSearchResponse
            pass
        elif message_type == 0x0206: # it's a connect response
            self._log('Parsing KnxConnectResponse')
            response = libknx.messages.KnxConnectionResponse(data)
            #print(response.header)
            #print(response.body)

            self.communication_channel = response.body['communication_channel_id']

            if not response.ERROR: # if no error happened
                self.device_alive = True
                if not self.tunnel_established: # we don't have a tunnel set up yet
                    # check if we received a tunnel response

                    # if its actually a tunnel response, we have a tunnel
                    self.tunnel_established = True
            else: # device is not alive and we didn't receive a KnxConnectionResponse, we should abort
                self.transport.close()
                sys.exit(1)

        elif message_type == 0x0421: # it's a tunneling ack
            self._log('Parsing KnxTunnelingAck')
            response = libknx.messages.KnxTunnellingAck(data)
            #print(response.header)
            #print(response.body)
        else:
            print('Unknown message type: '.format(message_type))
            return

        # device is alive and tunnel is established, do the actual stuff
        self.knx_turn_on_test()


    def error_received(self, exc):
        self._log('An error occured: {}'.format(exc))


    def connection_lost(self, exc):
        self._log('Connection lost: {}'.format(exc))


    def knx_turn_on_test(self):
        # try to turn on the light on device 0/0/1
        packet = libknx.messages.KnxTunnellingRequest(port=self.sockname[1], communication_channel=self.communication_channel)
        packet.set_source_ip(self.sockname[0])
        packet.pack_knx_message()

        print(packet.get_message())
        self.transport.sendto(packet.get_message())
        self._log('KnxTunnellingRequest sent')



class KnxScanner():

    def __init__(self, targets=[], max_tasks=10, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.max_tasks = max_tasks
        # the Queue contains all targets
        self.q = Queue(loop=self.loop)
        self.alive_targets = set()

        # save some timing information
        self.t0 = time.time()
        self.t1 = None


    @asyncio.coroutine
    def knx_connection(self, target):
        """Do the KnxConnection stuff here."""
        pass


    @asyncio.coroutine
    def knx_find_bus_devices(self, target):
        """Find devices on the bus accessible via target (which should be a KNX gateway)."""
        self.loop.create_datagram_endpoint(
            KnxConnection,
            remote_addr=(target, KNX_UDP_PORT)
        )


    @asyncio.coroutine
    def work(self):
        """Process the Queue items."""
        try:
            while True:
                target = yield from self.q.get()
                assert target in self.alive_targets
                yield from self.knx_connection(target)
                self.q.task_done()
        except asyncio.CancelledError:
            pass


    @asyncio.coroutine
    def scan(self):
        """The function that will be called by run_until_complete()."""
        workers = [asyncio.Task(self.work(), loop=self.loop)
                   for _ in range(self.max_tasks)]
        self.t0 = time.time()
        yield from self.q.join()
        self.t1 = time.time()
        for w in workers:
            w.cancel()


    @asyncio.coroutine
    def knx_description(self, target):
        """Send a KnxDescription request to see if target is a KNX device."""
        pass


def main():
    # TODO: parse command line arguments
    # args = ARGS.parse_args()

    # TODO: do logging stuff
    loop = asyncio.get_event_loop()

    # TODO: create a KnxScanner instance
    scanner = KnxScanner(targets=[])

    try:
        # testing, will be removed eventually
        loop.run_until_complete(
            loop.create_datagram_endpoint(
                KnxConnection,
                remote_addr=('192.168.178.11', 3671)
            )
        )
        # the proposed implementation
        loop.run_until_complete(scanner.scan())
    finally:
        loop.close()


if __name__ == "__main__":
    main()