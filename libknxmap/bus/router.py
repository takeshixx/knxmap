import logging
import asyncio

from libknxmap.messages import *
from libknxmap.core import *

LOGGER = logging.getLogger(__name__)


class KnxRoutingConnection(asyncio.DatagramProtocol):
    # TODO: implement routing
    """Routing is used to send KNX messages to multiple devices without any
    connection setup (in contrast to tunnelling).

        * uses UDP multicast (224.0.23.12) packets to port 3671

        * no confirmation of successful transmission

        * will send message to group address if supplied group address is known
        by devices?"""
    def __init__(self, future, loop=None):
        self.future = future
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        pass

    def _send(self, message):
        self.transport.get_extra_info('socket').sendto(message.get_message(), ('224.0.23.12', 3671))
