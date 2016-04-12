"""This module will include code that scans on the KNX bus for
available devices."""
import sys
import logging
import asyncio

from .messages import *

LOGGER = logging.getLogger(__name__)


class KnxBusConnection:
    """Communicate with bus devices via a KNX gateway using TunnellingRequests."""

    tunnel_established = False
    communication_channel = None

    def __init__(self, loop=None, port=55775):
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None


    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')

        LOGGER.debug('Connection established')


        # initialize connection request
        packet = libknx.messages.KnxConnectionRequest(port=self.sockname[1])
        packet.set_source_ip(self.sockname[0])
        packet.pack_knx_message()

        self.transport.sendto(packet.get_message())
        LOGGER.debug('KnxConnectionRequest sent')


    def datagram_received(self, data, addr):
        LOGGER.debug('Data received')
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


        if message_type == 0x0206: # it's a connect response
            LOGGER.info('Parsing KnxConnectResponse')
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
            LOGGER.info('Parsing KnxTunnelingAck')
            response = libknx.messages.KnxTunnellingAck(data)
            #print(response.header)
            #print(response.body)
        else:
            LOGGER.error('Unknown message type: '.format(message_type))
            return

        # device is alive and tunnel is established, do the actual stuff
        self.knx_tunnelling_test()


    def knx_tunnelling_test(self):
        # try to turn on the light on device 0/0/1
        packet = libknx.messages.KnxTunnellingRequest(
            port=self.sockname[1], communication_channel=self.communication_channel)
        packet.set_source_ip(self.sockname[0])
        packet.pack_knx_message()

        print(packet.get_message())
        self.transport.sendto(packet.get_message())
        self._log('KnxTunnellingRequest sent')