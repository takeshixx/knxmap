"""Implementation of KNXnet/IP communication with KNXnet/IP gateways."""
import asyncio
import logging

from knxmap.data.constants import *
from knxmap.messages import parse_message, KnxSearchRequest, KnxSearchResponse, KnxDescriptionRequest, \
                            KnxDescriptionResponse, KnxRemoteDiagnosticRequest, \
                            KnxRemoteDiagnosticResponse

__all__ = ['KnxGatewaySearch',
           'KnxGatewayDescription']

LOGGER = logging.getLogger(__name__)


class KnxGatewaySearch(asyncio.DatagramProtocol):
    """A protocol implementation for searching KNXnet/IP gateways via
    multicast messages. The protocol will hold a set responses with
    all the KNXnet/IP gateway responses."""
    def __init__(self, loop=None, multicast_addr=KNX_CONSTANTS.get('MULTICAST_ADDR'),
                 port=KNX_CONSTANTS.get('DEFAULT_PORT')):
        self.loop = loop or asyncio.get_event_loop()
        self.multicast_addr = multicast_addr
        self.port = port
        self.transport = None
        self.peername = None
        self.sockname = None
        self.responses = set()
        self.diagnostic_responses = set()

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        packet = KnxSearchRequest(sockname=self.sockname)
        LOGGER.trace_outgoing(packet)
        packet = packet.get_message()
        self.transport.get_extra_info('socket').sendto(packet, (self.multicast_addr, self.port))

    def datagram_received(self, data, addr):
        knx_message = parse_message(data)
        if knx_message:
            knx_message.set_peer(addr)
            LOGGER.trace_incoming(knx_message)
            if isinstance(knx_message, KnxSearchResponse):
                self.responses.add((addr, knx_message))
            elif isinstance(knx_message, KnxRemoteDiagnosticResponse):
                self.diagnostic_responses.add((addr, knx_message))

    def send_diagnostic_request(self, selector=None):
        packet = KnxRemoteDiagnosticRequest(sockname=self.sockname)
        LOGGER.trace_outgoing(packet)
        packet = packet.get_message()
        self.transport.get_extra_info('socket').sendto(packet, (self.multicast_addr, self.port))


class KnxGatewayDescription(asyncio.DatagramProtocol):
    """Protocol implementation for KNXnet/IP description requests."""
    def __init__(self, future, loop=None, timeout=2, nat_mode=False):
        self.future = future
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.peername = None
        self.sockname = None
        self.wait = None
        self.timeout = timeout
        self.nat_mode = nat_mode

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        self.wait = self.loop.call_later(self.timeout, self.connection_timeout)
        if self.nat_mode:
            packet = KnxDescriptionRequest(sockname=('0.0.0.0', 0))
        else:
            packet = KnxDescriptionRequest(sockname=self.sockname)
        LOGGER.trace_outgoing(packet)
        self.transport.sendto(packet.get_message())

    def connection_timeout(self):
        self.transport.close()
        self.future.set_result(False)

    def datagram_received(self, data, addr):
        self.wait.cancel()
        self.transport.close()
        knx_message = parse_message(data)
        if knx_message:
            knx_message.set_peer(addr)
            LOGGER.trace_incoming(knx_message)
            if isinstance(knx_message, KnxDescriptionResponse):
                self.future.set_result(knx_message)
            else:
                self.future.set_result(False)
