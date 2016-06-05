"""This module will include code that scans on the KNX bus for
available devices."""
import logging
import asyncio
import collections
import struct

from .messages import *
from .core import *

LOGGER = logging.getLogger(__name__)


class KnxTunnelConnection(asyncio.DatagramProtocol):
    """Communicate with bus devices via a KNX gateway using TunnellingRequests. A tunneling
    connection is always used if the bus destination is a physical KNX address."""
    def __init__(self, future, loop=None):
        self.future = future
        self.target_futures = dict()
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.tunnel_established = False
        self.communication_channel = None
        self.sequence_count = 0
        self.tpci_sequence_count = 0
        self.knx_source_address = None # TODO: probably not needed

        self.response_queue = list()

    def connection_made(self, transport):
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        connect_request = KnxConnectRequest(sockname=self.sockname)
        self.transport.sendto(connect_request.get_message())
        # Schedule CONNECTIONSTATE_REQUEST to keep the connection alive
        self.loop.call_later(50, self.knx_keep_alive)
        self.loop.call_later(4, self.poll_response_queue)

    def poll_response_queue(self):
        if self.response_queue:
            for response in self.response_queue:
                knx_source = response.parse_knx_address(response.body.get('cemi').get('knx_source'))
                knx_dest = response.parse_knx_address(response.body.get('cemi').get('knx_destination'))
                if not knx_source and not knx_dest:
                    continue

                if knx_dest in self.target_futures.keys():
                    if not self.target_futures[knx_dest].done():
                        self.target_futures[knx_dest].set_result(response)
                    del self.target_futures[knx_dest]
                elif knx_source in self.target_futures.keys():
                    if not self.target_futures[knx_source].done():
                        self.target_futures[knx_source].set_result(response)
                    del self.target_futures[knx_source]

        self.loop.call_later(2, self.poll_response_queue)

    def response_timeout(self, target):
        if target in self.target_futures.keys():
            if not self.target_futures[target].done():
                self.target_futures[target].set_result(False)
                del self.target_futures[target]

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
            knx_source = knx_message.parse_knx_address(knx_message.body.get('cemi').get('knx_source'))
            knx_dest = knx_message.parse_knx_address(knx_message.body.get('cemi').get('knx_destination'))

            if CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.con' and \
                    (knx_message.body.get('cemi').get('tpci').get('type') == TPCI_TYPES['UCD'] or
                     knx_message.body.get('cemi').get('tpci').get('type') == TPCI_TYPES['NCD']):

                if knx_message.body.get('cemi').get('controlfield_1').get('confirm'):
                    LOGGER.debug('KNX device not alive: {}'.format(knx_dest))
                    if knx_dest in self.target_futures.keys():
                        if not self.target_futures[knx_dest].done():
                           self.target_futures[knx_dest].set_result(False)
                           del self.target_futures[knx_dest]
                    else:
                        self.response_queue.append(knx_message)

                else:
                    LOGGER.debug('KNX device is alive: {}'.format(knx_dest))
                    if knx_dest in self.target_futures.keys():
                        if not self.target_futures[knx_dest].done():
                           self.target_futures[knx_dest].set_result(True)
                           del self.target_futures[knx_dest]
                    else:
                        self.response_queue.append(knx_message)

            elif CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.con' and \
                            knx_message.body.get('cemi').get('tpci').get('type') == TPCI_TYPES['NDP']:

                # if we get a confirmation for our device descriptor request, check if L_Data.ind arrives
                if knx_message.body.get('cemi').get('apci') == APCI_TYPES.get('A_DeviceDescriptor_Read'):
                    self.loop.call_later(3, self.response_timeout, knx_dest)

            elif CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.ind' and \
                            knx_message.body.get('cemi').get('tpci').get('type') == TPCI_TYPES['UCD']:

                if knx_message.body.get('cemi').get('tpci').get('status') is 1:
                    if knx_dest in self.target_futures.keys():
                        if not self.target_futures[knx_dest].done():
                            self.target_futures[knx_dest].set_result(False)
                            del self.target_futures[knx_dest]
                    else:
                        self.response_queue.append(knx_message)

            elif CEMI_PRIMITIVES[knx_message.body.get('cemi').get('message_code')] == 'L_Data.ind' and \
                            knx_message.body.get('cemi').get('tpci').get('type') == TPCI_TYPES['NDP']:

                if knx_message.body.get('cemi').get('apci') == APCI_TYPES['A_DeviceDescriptor_Response']:
                    if knx_source in self.target_futures.keys():
                        if not self.target_futures[knx_source].done():
                            self.target_futures[knx_source].set_result(knx_message)
                            del self.target_futures[knx_source]
                    else:
                        self.response_queue.append(knx_message)

                elif knx_message.body.get('cemi').get('apci') == APCI_TYPES['A_Authorize_Response']:

                    LOGGER.info(
                        '{}: AUTHORIZE_RESPONSE DATA: {}'.format(knx_source, knx_message.body.get('cemi').get('data')))

                    if knx_source in self.target_futures.keys():
                        if not self.target_futures[knx_source].done():
                            self.target_futures[knx_source].set_result(knx_message)
                            del self.target_futures[knx_source]
                    else:
                        self.response_queue.append(knx_message)

                elif knx_message.body.get('cemi').get('apci') == APCI_TYPES['A_PropertyValue_Response']:

                    LOGGER.info('{}/{}/{}: PROPERTY_VALUE_RESPONSE DATA: {}'.format(
                        self.peername[0], knx_source, knx_dest, knx_message.body.get('cemi').get('data')[4:]))

                    #data = knx_message.body.get('cemi').get('data')[4:]

                    if knx_source in self.target_futures.keys():
                        if not self.target_futures[knx_source].done():
                            self.target_futures[knx_source].set_result(knx_message)
                            del self.target_futures[knx_source]
                    else:
                        self.response_queue.append(knx_message)

                elif knx_message.body.get('cemi').get('apci') == APCI_TYPES['A_Memory_Response']:

                    LOGGER.info('{}/{}: MEMORY_RESPONSE DATA: {}'.format(
                        self.peername[0], knx_source, knx_message.body.get('cemi').get('data')))

                    #data = knx_message.body.get('cemi').get('data')[2:]

                    if knx_source in self.target_futures.keys():
                        if not self.target_futures[knx_source].done():
                            self.target_futures[knx_source].set_result(knx_message)
                            del self.target_futures[knx_source]
                    else:
                        self.response_queue.append(knx_message)

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

    def send_data(self, data, target):
        """A wrapper for sendto() that takes care of incrementing the sequence counter.

        Note: the sequence counter field is only 1 byte. After incrementing the counter
        to 255, it seems to be OK to just start over from 0. At least this applies
        to the tested devices."""
        f = asyncio.Future()
        self.target_futures[target] = f
        self.transport.sendto(data)
        if self.sequence_count == 255:
            self.sequence_count = 0
        else:
            self.sequence_count += 1
        return f

    def make_tunnel_request(self, knx_destination):
        """A helper function that returns a KnxTunnellingRequest that is already predefined
        for the current tunnel connection. It already sets the communication channel, the
        sequence count, the KNX source address and the peer which are all handled by the
        protocol instance anyway."""
        tunnel_request = KnxTunnellingRequest(
            communication_channel=self.communication_channel,
            sequence_count=self.sequence_count,
            knx_source=self.knx_source_address,
            knx_destination=knx_destination)
        tunnel_request.set_peer(self.transport.get_extra_info('sockname'))
        return tunnel_request

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

    def knx_tpci_disconnect(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.unnumbered_control_data('DISCONNECT')
        self.transport.sendto(tunnel_request.get_message())


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


class KnxBusMonitor(KnxTunnelConnection):
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