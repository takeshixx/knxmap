import asyncio
import logging

from knxmap.data.constants import *
from knxmap.messages import KnxRoutingIndication

LOGGER = logging.getLogger(__name__)


class KnxRoutingConnection(asyncio.DatagramProtocol):
    # TODO: implement routing
    """Routing is used to send KNX messages to multiple devices without any
    connection setup (in contrast to tunnelling)."""

    def __init__(self, target, value, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.target = target
        self.value = value

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        packet = KnxRoutingIndication(knx_destination=self.target)
        packet.apci_group_value_write(value=self.value)
        LOGGER.trace_outgoing(packet)
        self.transport.get_extra_info('socket').sendto(packet.get_message(),
                                                       (KNX_CONSTANTS.get('MULTICAST_ADDR'),
                                                        KNX_CONSTANTS.get('DEFAULT_PORT')))
