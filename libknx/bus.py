"""This module will include code that scans on the KNX bus for
available devices."""
import sys
import logging
import asyncio
import struct

from .messages import *
from .core import *

LOGGER = logging.getLogger(__name__)


class KnxTunnelConnection(asyncio.DatagramProtocol):
    """Communicate with bus devices via a KNX gateway using TunnellingRequests."""

    # TODO: a tunnelling connection is always used when the destination
    # is a physical KNX address

    def __init__(self, future, loop=None, group_monitor=True):
        self.future = future
        self.target_futures = {}
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.group_monitor = group_monitor
        self.tunnel_established = False
        self.communication_channel = None
        self.sequence_count = 0
        self.knx_source_address = None # TODO: probably not needed

    def connection_made(self, transport):
        LOGGER.debug('Connection established')
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        if self.group_monitor:
            # Create a TUNNEL_LINKLAYER layer request (default)
            connect_request = KnxConnectRequest(sockname=self.sockname)
        else:
            # Create a TUNNEL_BUSMONITOR layer request
            connect_request = KnxConnectRequest(sockname=self.sockname, layer_type=0x80)
        self.transport.sendto(connect_request.get_message())
        # Send CONNECTIONSTATE_REQUEST to keep the connection alive
        self.loop.call_later(50, self.knx_keep_alive)

    def datagram_received(self, data, addr):
        LOGGER.debug('data: {}'.format(data))
        knx_message = parse_message(data)

        if not knx_message:
            LOGGER.error('Invalid KNX message: {}'.format(data))
            self.knx_tunnel_disconnect()
            self.transport.close()
            self.future.set_result(None)
            return

        if isinstance(knx_message, KnxConnectResponse):
            if not knx_message.ERROR:
                if not self.tunnel_established:
                    self.tunnel_established = True
                self.communication_channel = knx_message.body.get('communication_channel_id')
                self.knx_source_address = knx_message.body.get('data_block').get('knx_address')
                self.future.set_result(True)
            else:
                LOGGER.error(knx_message.ERROR)
                self.transport.close()
                self.future.set_result(None)
        elif isinstance(knx_message, KnxTunnellingRequest):
            # TODO: check this more central, e.g. in the KnxMessage class
            def is_set_bit(value, pos):
                if (value & (2 ** pos)) is not 0:
                    return True
                else:
                    return False

            if CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.con':
                ctrl_field1 = knx_message.body.get('cemi').get('controlfield_1')
                knx_dest = knx_message.parse_knx_address(knx_message.body.get('cemi').get('knx_destination'))

                # TODO: if check is successful, add it to a global list
                if is_set_bit(ctrl_field1, 0):
                    LOGGER.debug('KNX device not alive: {}'.format(knx_dest))
                    self.target_futures[knx_dest].set_result(False)
                else:
                    LOGGER.debug('KNX device is alive: {}'.format(knx_dest))
                    self.target_futures[knx_dest].set_result(True)

            if CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.con' or \
                    CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.ind':
                tunnelling_ack = KnxTunnellingAck(
                    communication_channel=knx_message.body.get('communication_channel_id'),
                    sequence_count=knx_message.body.get('sequence_counter'))
                self.transport.sendto(tunnelling_ack.get_message())
        elif isinstance(knx_message, KnxTunnellingAck):
            pass
        elif isinstance(knx_message, KnxConnectionStateResponse):
            # After receiving a CONNECTIONSTATE_RESPONSE shedule the next one
            self.loop.call_later(50, self.knx_keep_alive)
        elif isinstance(knx_message, KnxDisconnectRequest):
            disconnect_response = KnxDisconnectResponse(communication_channel=self.communication_channel)
            self.transport.sendto(disconnect_response.get_message())
            self.transport.close()
            if not self.future.done():
                self.future.set_result(None)
        elif isinstance(knx_message, KnxDisconnectResponse):
            self.transport.close()
            if not self.future.done():
                self.future.set_result(None)

    def knx_keep_alive(self):
        """Sending CONNECTIONSTATE_REQUESTS periodically to keep the connection alive."""
        connection_state = KnxConnectionStateRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        self.transport.sendto(connection_state.get_message())

    def knx_tunnel_disconnect(self):
        """Close the tunnel connection with a DISCONNECT_REQUEST."""
        disconnect_request = KnxDisconnectRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        self.transport.sendto(disconnect_request.get_message())


class KnxRoutingConnection(asyncio.DatagramProtocol):

    # TODO: routing is used to send KNX messages to multiple devices
    # without any connection setup (in contrast to tunnelling)

    # TODO: uses UDP multicast (224.0.23.12) packets to port 3671

    # TODO: no confirmation of successful transmission

    # TODO: will send message to group address if supplied group address
    # is known by devices?

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


class KnxBusMonitor(asyncio.DatagramProtocol):
    """Implementation of bus_monitor_mode and group_monitor_mode."""
    def __init__(self, future, loop=None, group_monitor=True):
        self.future = future
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.group_monitor = group_monitor
        self.tunnel_established = False
        self.communication_channel = None
        self.sequence_count = 0

    def connection_made(self, transport):
        LOGGER.debug('Connection established')
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        if self.group_monitor:
            # Create a TUNNEL_LINKLAYER layer request (default)
            connect_request = KnxConnectRequest(sockname=self.sockname)
        else:
            # Create a TUNNEL_BUSMONITOR layer request
            connect_request = KnxConnectRequest(sockname=self.sockname, layer_type=0x80)
        self.transport.sendto(connect_request.get_message())
        # Send CONNECTIONSTATE_REQUEST to keep the connection alive
        self.loop.call_later(50, self.knx_keep_alive)

    def datagram_received(self, data, addr):
        LOGGER.debug('data: {}'.format(data))
        knx_message = parse_message(data)

        if not knx_message:
            LOGGER.error('Invalid KNX message: {}'.format(data))
            self.knx_tunnel_disconnect()
            self.transport.close()
            self.future.set_result(None)
            return

        if isinstance(knx_message, KnxConnectResponse):
            if not knx_message.ERROR:
                if not self.tunnel_established:
                    self.tunnel_established = True
                self.communication_channel = knx_message.body.get('communication_channel_id')
            else:
                if not self.group_monitor and knx_message.ERROR_CODE == 0x23:
                    LOGGER.error('Device does not support BUSMONITOR, try --group-monitor instead')
                else:
                    LOGGER.error('Connection setup error: {}'.format(knx_message.ERROR))
                self.transport.close()
                self.future.set_result(None)
        elif isinstance(knx_message, KnxTunnellingRequest):
            self.print_message(knx_message)
            if CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.con' or \
                    CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.ind':
                tunnelling_ack = KnxTunnellingAck(
                    communication_channel=knx_message.body.get('communication_channel_id'),
                    sequence_count=knx_message.body.get('sequence_counter'))
                self.transport.sendto(tunnelling_ack.get_message())
        elif isinstance(knx_message, KnxTunnellingAck):
            self.print_message(knx_message)
        elif isinstance(knx_message, KnxConnectionStateResponse):
            # After receiving a CONNECTIONSTATE_RESPONSE shedule the next one
            self.loop.call_later(50, self.knx_keep_alive)
        elif isinstance(knx_message, KnxDisconnectRequest):
            connect_response = KnxDisconnectResponse(communication_channel=self.communication_channel)
            self.transport.sendto(connect_response.get_message())
            self.transport.close()
            self.future.set_result(None)
        elif isinstance(knx_message, KnxDisconnectResponse):
            self.transport.close()
            self.future.set_result(None)

    def print_message(self, message):
        """A generic message printing function. It defines a format for the monitoring modes."""
        assert isinstance(message, KnxTunnellingRequest)
        if self.group_monitor:
            format = '[ chan_id: {}, seq_no: {}, message_code: {}, source_addr: {}, dest_addr: {}, tcpi: {}, apci: {} ]'.format(
                message.body.get('communication_channel_id'),
                message.body.get('sequence_counter'),
                CEMI_PRIMITIVES[message.body.get('cemi').get('message_code')],
                message.parse_knx_address(message.body.get('cemi').get('knx_source')),
                message.parse_knx_group_address(message.body.get('cemi').get('knx_destination')),
                message.body.get('cemi').get('tcpi'),
                message.body.get('cemi').get('apci'))
        else:
            format = '[ chan_id: {}, seq_no: {}, message_code: {}, raw_frame: {} ]'.format(
                message.body.get('communication_channel_id'),
                message.body.get('sequence_counter'),
                CEMI_PRIMITIVES[message.body.get('cemi').get('message_code')],
                message.body.get('cemi').get('raw_frame'))
        LOGGER.info(format)

    def knx_keep_alive(self):
        """Sending CONNECTIONSTATE_REQUESTS periodically to keep the connection alive."""
        connection_state = KnxConnectionStateRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        self.transport.sendto(connection_state.get_message())

    def knx_tunnel_disconnect(self):
        """Close the tunnel connection with a DISCONNECT_REQUEST."""
        disconnect_request = KnxDisconnectRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        self.transport.sendto(disconnect_request.get_message())
