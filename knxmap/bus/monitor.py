import asyncio
import logging

from knxmap.bus.tunnel import KnxTunnelConnection
from knxmap.data.constants import *
from knxmap.messages import parse_message, KnxConnectRequest, KnxConnectResponse, \
                            KnxTunnellingRequest, KnxTunnellingAck, KnxConnectionStateResponse, \
                            KnxDisconnectRequest, KnxDisconnectResponse

LOGGER = logging.getLogger(__name__)


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
            connect_request = KnxConnectRequest(sockname=self.sockname, layer_type='TUNNEL_BUSMONITOR')
        self.transport.sendto(connect_request.get_message())
        # Send CONNECTIONSTATE_REQUEST to keep the connection alive
        self.loop.call_later(50, self.knx_keep_alive)

    def datagram_received(self, data, addr):
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
        cemi = tpci = apci= {}
        if message.body.get('cemi'):
            cemi = message.body.get('cemi')
            if cemi.get('tpci'):
                tpci = cemi.get('tpci')
                if tpci.get('apci'):
                    apci = tpci.get('apci')
        if cemi.get('controlfield_2')and cemi.get('controlfield_2').get('address_type'):
            dst_addr = message.parse_knx_group_address(cemi.get('knx_destination'))
        else:
            dst_addr = message.parse_knx_address(cemi.get('knx_destination'))
        if self.group_monitor:
            format = ('[ chan_id: {chan_id}, seq_no: {seq_no}, message_code: {msg_code}, '
                      'source_addr: {src_addr}, dest_addr: {dst_addr}, tpci_type: {tpci_type}, '
                      'tpci_seq: {tpci_seq}, apci_type: {apci_type}, apci_data: {apci_data} ]').format(
                chan_id=message.body.get('communication_channel_id'),
                seq_no=message.body.get('sequence_counter'),
                msg_code=CEMI_PRIMITIVES[cemi.get('message_code')],
                src_addr=message.parse_knx_address(cemi.get('knx_source')),
                dst_addr=dst_addr,
                tpci_type=_CEMI_TPCI_TYPES.get(tpci.get('type')),
                tpci_seq=tpci.get('sequence'),
                apci_type=_CEMI_APCI_TYPES.get(apci.get('type')),
                apci_data=apci.get('data'))
        else:
            format = ('[ chan_id: {chan_id}, seq_no: {seq_no}, message_code: {msg_code}, '
                      'raw_frame: {raw_frame} ]').format(
                chan_id=message.body.get('communication_channel_id'),
                seq_no=message.body.get('sequence_counter'),
                msg_code=CEMI_PRIMITIVES[cemi.get('message_code')],
                raw_frame=cemi.get('raw_frame'))
        LOGGER.info(format)
