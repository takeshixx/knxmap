"""Implementation of KNXnet/IP communication with KNXnet/IP gateways."""
import asyncio
import logging

from .core import *
from .messages import *

__all__ = ['KnxGatewaySearch',
           'KnxGatewayDescription']

LOGGER = logging.getLogger(__name__)

class KnxGatewaySearch(asyncio.DatagramProtocol):
    """A protocol implementation for searching KNXnet/IP gateways via
    multicast messages. The protocol will hold a set responses with
    all the KNXnet/IP gateway responses."""
    def __init__(self, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.responses = set()

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        packet = KnxSearchRequest(sockname=self.sockname)
        self.transport.get_extra_info('socket').sendto(packet.get_message(),
               (KNX_CONSTANTS.get('MULTICAST_ADDR'),
                KNX_CONSTANTS.get('DEFAULT_PORT')))

    def datagram_received(self, data, addr):
        knx_message = parse_message(data)
        if knx_message and isinstance(knx_message, KnxSearchResponse):
            self.responses.add((addr, knx_message))


class KnxGatewayDescription(asyncio.DatagramProtocol):
    """Protocol implelemtation for KNXnet/IP description requests."""
    def __init__(self, future, loop=None, timeout=2):
        self.future = future
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.timeout = timeout

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        self.wait = self.loop.call_later(self.timeout, self.connection_timeout)
        packet = KnxDescriptionRequest(sockname=self.sockname)
        self.transport.sendto(packet.get_message())

    def connection_timeout(self):
        self.transport.close()
        self.future.set_result(False)

    def datagram_received(self, data, addr):
        self.wait.cancel()
        self.transport.close()
        knx_message = parse_message(data)
        if knx_message and isinstance(knx_message, KnxDescriptionResponse):
            self.future.set_result(knx_message)
        else:
            self.future.set_result(False)
