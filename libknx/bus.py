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
    def __init__(self, future, loop=None):
        self.future = future
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.tunnel_established = False
        self.communication_channel = None
        self.sequence_count = 0
        self.gateway_knx_address = '0.0.0'

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')

        LOGGER.debug('Connection established')

        connect_request = KnxConnectRequest(sockname=self.sockname)
        connect_request.pack_knx_message()
        self.transport.sendto(connect_request.get_message())

    def datagram_received(self, data, addr):
        LOGGER.debug('data: {}'.format(data))

        try:
            # parse the KNX header to see what type of KNX message it is
            header = {}
            header['header_length'], \
            header['protocol_version'], \
            header['service_type'], \
            header['total_length'] = struct.unpack('>BBHH', data[:6])
            message_type = int(header['service_type'])
        except Exception as e:
            LOGGER.exception(e)
            self.transport.close()
            return

        if message_type == 0x0206: # CONNECT_RESPONSE
            LOGGER.debug('Parsing KnxConnectResponse')
            response = KnxConnectResponse(data)

            if not response.ERROR:
                if not self.tunnel_established: # we don't have a tunnel set up yet
                    self.tunnel_established = True

                self.communication_channel = response.body['communication_channel_id']
                LOGGER.info('Channel ID: {}'.format(self.communication_channel))

                self.future.set_result(True)
            else: # device is not alive and we didn't receive a KnxConnectionResponse, we should abort
                LOGGER.info('CONNECT_RESPONSE ERROR: {}'.format(response.ERROR))
                self.transport.close()
                self.future.set_result(None)

        elif message_type == 0x0420: # TUNNELLING_REQUEST
            # KNXnet/IP gateway sends back confirmation messages in TUNNELLING_REQUESTS
            LOGGER.debug('Parsing KnxTunnelingRequest')
            response = KnxTunnellingRequest(data)

            if CEMI_PRIMITIVES[response.body.get('cemi').get('message_code')] == 'L_Data.con':
                # Only if it's a confirmation message we will respond
                tunnelling_ack = KnxTunnellingAck(
                    communication_channel=response.body.get('communication_channel_id'),
                    sequence_count=response.body.get('sequence_counter'))
                tunnelling_ack.pack_knx_message()
                self.transport.sendto(tunnelling_ack.get_message())


        elif message_type == 0x0421: # TUNNELLING_ACK
            LOGGER.debug('Parsing KnxTunnelingAck')
            response = KnxTunnellingAck(data)

            # TODO: probably not even needed
            self.sequence_count += 1


        elif message_type == 0x0209: # DISCONNECT_REQUEST
            LOGGER.debug('Parsing KnxDisconnectRequest')
            response = KnxDisconnectResponse(data)

        elif message_type == 0x020a: # DISCONNECT_RESPONSE
            LOGGER.debug('Parsing KnxDisconnectResponse')
            response = KnxDisconnectResponse(data)
            self.transport.close()
        else:
            LOGGER.error('Unknown message type: '.format(message_type))
            return


    def tunnel_disconnect(self):
        """Close the tunnel connection with a DISCONNECT_REQUEST."""
        disconnect_request = KnxDisconnectRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        disconnect_request.pack_knx_message()
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

    # TODO: monitors messages from the bus

    def __init__(self, future, loop=None):
        self.future = future
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.tunnel_established = False
        self.communication_channel = None
        self.sequence_count = 0

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')

        LOGGER.debug('Connection established')

        connect_request = KnxConnectRequest(sockname=self.sockname)
        connect_request.pack_knx_message()
        self.transport.sendto(connect_request.get_message())
        # Send CONNECTIONSTATE_REQUEST to keep the connection alive
        self.loop.call_later(50, self.keep_alive)

    def datagram_received(self, data, addr):
        LOGGER.debug('data: {}'.format(data))
        try:
            # parse the KNX header to see what type of KNX message it is
            header = {}
            header['header_length'], \
            header['protocol_version'], \
            header['service_type'], \
            header['total_length'] = struct.unpack('>BBHH', data[:6])
            message_type = int(header['service_type'])
        except Exception as e:
            LOGGER.exception(e)
            self.transport.close()
            return

        if message_type == 0x0206: # CONNECT_RESPONSE
            LOGGER.debug('Parsing KnxConnectResponse')
            response = KnxConnectResponse(data)

            if not response.ERROR:
                if not self.tunnel_established: # we don't have a tunnel set up yet
                    self.tunnel_established = True
                self.communication_channel = response.body['communication_channel_id']
            else: # device is not alive and we didn't receive a KnxConnectionResponse, we should abort
                LOGGER.error('CONNECT_RESPONSE ERROR: {}'.format(response.ERROR))
                self.transport.close()
                self.future.set_result(None)

        elif message_type == 0x0420: # TUNNELLING_REQUEST
            # KNXnet/IP gateway sends back confirmation messages in TUNNELLING_REQUESTS
            response = KnxTunnellingRequest(data)
            self.print_message(response)

            if CEMI_PRIMITIVES[response.body.get('cemi').get('message_code')] == 'L_Data.con':
                # Only if it's a confirmation message we will respond
                tunnelling_ack = KnxTunnellingAck(
                    communication_channel=response.body.get('communication_channel_id'),
                    sequence_count=response.body.get('sequence_counter'))
                tunnelling_ack.pack_knx_message()
                self.transport.sendto(tunnelling_ack.get_message())


        elif message_type == 0x0421: # TUNNELLING_ACK
            LOGGER.debug('Parsing KnxTunnelingAck')
            response = KnxTunnellingAck(data)

            # TODO: probably not even needed
            self.sequence_count += 1
        elif message_type == 0x0208: # CONNECTIONSTATE_RESPONSE
            LOGGER.debug('Parsing KnxConnectionStateResponse')
            response = KnxConnectionStateResponse(data)
            # After receiving a CONNECTIONSTATE_RESPONSE shedule the next one
            self.loop.call_later(50, self.keep_alive)

        elif message_type == 0x0209: # DISCONNECT_REQUEST
            LOGGER.debug('Parsing KnxDisconnectRequest')
            response = KnxDisconnectResponse(data)

            connect_response = KnxDisconnectResponse(communication_channel=self.communication_channel)
            connect_response.pack_knx_message()
            self.transport.sendto(connect_response.get_message())

        elif message_type == 0x020a: # DISCONNECT_RESPONSE
            LOGGER.debug('Parsing KnxDisconnectResponse')
            response = KnxDisconnectResponse(data)
            self.transport.close()
        else:
            LOGGER.error('Unknown message type: '.format(message_type))
            return

    def print_message(self, message):
        assert isinstance(message, KnxTunnellingRequest)
        format = '[ chan_id: {}, seq_no: {}, message_code: {}, source_addr: {}, dest_addr: {}, tcpi: {}, apci: {} ]'.format(
            message.body.get('communication_channel_id'),
            message.body.get('sequence_counter'),
            CEMI_PRIMITIVES[message.body.get('cemi').get('message_code')],
            message.parse_knx_address(message.body.get('cemi').get('knx_source')),
            message.parse_knx_group_address(message.body.get('cemi').get('knx_destination')),
            message.body.get('cemi').get('tcpi'),
            message.body.get('cemi').get('apci'))
        LOGGER.info(format)

    def keep_alive(self):
        connection_state = KnxConnectionStateRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        connection_state.pack_knx_message()
        self.transport.sendto(connection_state.get_message())

    def tunnel_disconnect(self):
        """Close the tunnel connection with a DISCONNECT_REQUEST."""
        disconnect_request = KnxDisconnectRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        disconnect_request.pack_knx_message()
        self.transport.sendto(disconnect_request.get_message())