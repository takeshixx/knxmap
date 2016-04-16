"""This module will include code that scans on the KNX bus for
available devices."""
import sys
import logging
import asyncio

from .messages import *

LOGGER = logging.getLogger(__name__)


class KnxBusConnection(asyncio.DatagramProtocol):
    """Communicate with bus devices via a KNX gateway using TunnellingRequests."""

    tunnel_established = False
    communication_channel = None
    sequence_count = 0
    gateway_knx_address = '0.0.0'

    def __init__(self, future, loop=None):
        self.future = future
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None


    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')

        LOGGER.debug('Connection established')

        connect_request = libknx.messages.KnxConnectionRequest(sockname=self.sockname)
        connect_request.pack_knx_message()
        self.transport.sendto(connect_request.get_message())
        LOGGER.debug('KnxConnectionRequest sent')


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

        LOGGER.info('message_type: {}'.format(message_type))

        if message_type == 0x0206: # CONNECT_RESPONSE
            LOGGER.info('Parsing KnxConnectResponse')
            response = libknx.KnxConnectionResponse(data)

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
            # TODO: why does the gateway send back TUNNELLING_REQUESTS?
            LOGGER.info('Parsing KnxTunnelingRequest')
            response = libknx.KnxTunnellingRequest(data)

            tunnelling_ack = libknx.KnxTunnellingAck(
                communication_channel=response.body.get('communication_channel_id'),
                sequence_count=response.body.get('sequence_counter'))
            tunnelling_ack.pack_knx_message()
            self.transport.sendto(tunnelling_ack.get_message())


        elif message_type == 0x0421: # TUNNELLING_ACK
            LOGGER.info('Parsing KnxTunnelingAck')
            response = libknx.KnxTunnellingAck(data)

            # TODO: probably not even needed
            self.sequence_count += 1


        elif message_type == 0x0209: # DISCONNECT_REQUEST
            LOGGER.info('Parsing KnxDisconnectRequest')
            response = libknx.KnxDisconnectResponse(data)

        elif message_type == 0x020a: # DISCONNECT_RESPONSE
            LOGGER.info('Parsing KnxDisconnectResponse')
            response = libknx.KnxDisconnectResponse(data)
            self.transport.close()
        else:
            LOGGER.error('Unknown message type: '.format(message_type))
            return


    def tunnel_disconnect(self):
        """Close the tunnel connection with a DISCONNECT_REQUEST."""
        disconnect_request = libknx.KnxDisconnectRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        disconnect_request.pack_knx_message()
        self.transport.sendto(disconnect_request.get_message())