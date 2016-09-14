import asyncio
import logging

from libknxmap.data.constants import *
from libknxmap.messages import *

LOGGER = logging.getLogger(__name__)


class KnxTunnelConnection(asyncio.DatagramProtocol):
    """Communicate with bus devices via a KNX gateway using TunnellingRequests. A tunneling
    connection is always used if the bus destination is a physical KNX address."""

    def __init__(self, future, connection_type=0x04, layer_type='TUNNEL_LINKLAYER', loop=None):
        self.future = future
        self.connection_type = connection_type
        self.layer_type = layer_type
        self.target_futures = dict()
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.tunnel_established = False
        self.communication_channel = None
        self.sequence_count = 0  # sequence counter in KNX body
        self.tpci_seq_counts = dict()  # NCD/NPD counter for each TPCI connection
        self.knx_source_address = None  # TODO: is the actual address needed? or just 0.0.0?
        self.response_queue = list()

    def connection_made(self, transport):
        """The connection setup function that takes care of:

        * Sending a KnxConnectRequest
        * Schedule KnxConnectionStateRequests
        * Schedule response queue polling"""
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        self.sockname = self.transport.get_extra_info('sockname')
        connect_request = KnxConnectRequest(
            sockname=self.sockname,
            connection_type=self.connection_type,
            layer_type=self.layer_type)
        self.transport.sendto(connect_request.get_message())
        # Schedule CONNECTIONSTATE_REQUEST to keep the connection alive
        self.loop.call_later(50, self.knx_keep_alive)
        self.loop.call_later(4, self.poll_response_queue)

    def poll_response_queue(self):
        """Check if there if there is a KNX message for a
        target that arrived out-of-band."""
        if self.response_queue:
            for response in self.response_queue:
                knx_src = response.parse_knx_address(response.body.get('cemi').get('knx_source'))
                knx_dst = response.parse_knx_address(response.body.get('cemi').get('knx_destination'))
                if not knx_src and not knx_dst:
                    continue

                if knx_dst in self.target_futures.keys():
                    if not self.target_futures[knx_dst].done():
                        self.target_futures[knx_dst].set_result(response)
                    del self.target_futures[knx_dst]
                elif knx_src in self.target_futures.keys():
                    if not self.target_futures[knx_src].done():
                        self.target_futures[knx_src].set_result(response)
                    del self.target_futures[knx_src]
        # Reschedule polling
        self.loop.call_later(2, self.poll_response_queue)

    def process_target(self, target, value, knx_msg=None):
        """When a L_Data.con NDP request request arrives after
        e.g. a A_DeviceDescriptor_Read, check if we get a
        L_Data.ind NDP request with the actual data.

        Note: Between a L_Data.con NDP and a L_Data.ind NDP
        there will most likely (pretty sure) be a L_Data.ind
        NCD request."""
        if target in self.target_futures.keys():
            if not self.target_futures[target].done():
                self.target_futures[target].set_result(value)
                del self.target_futures[target]
        else:
            if isinstance(value, KnxMessage):
                # If value is a KnxMessage itself,
                # jsut add it to the response_queue.
                self.response_queue.append(value)
            elif knx_msg and isinstance(knx_msg, KnxMessage):
                # If knx_msg is set, append it to
                # the response_queue.
                self.response_queue.append(knx_msg)

    def datagram_received(self, data, addr):
        """This function gets called whenever a data packet is received. It
        will try to parse the incoming KNX message and delegate further
        processing to the corresponding service handler (see KNX_SERVICES in
        the core module)."""
        knx_msg = parse_message(data)
        if not knx_msg:
            LOGGER.error('Invalid KNX message: {}'.format(data))
            self.knx_tunnel_disconnect()
            self.transport.close()
            self.future.set_result(None)
            return
        knx_service_type = knx_msg.header.get('service_type') >> 8
        if knx_service_type is 0x02:  # Core
            self.handle_core_services(knx_msg)
        elif knx_service_type is 0x03:  # Device Management
            self.handle_configuration_services(knx_msg)
        elif knx_service_type is 0x04:  # Tunnelling
            self.handle_tunnel_services(knx_msg)
        else:
            LOGGER.error('Service not implemented: {}'.format(KNX_SERVICES.get(knx_service_type)))

    def handle_core_services(self, knx_msg):
        if isinstance(knx_msg, KnxConnectResponse):
            if not knx_msg.ERROR:
                if not self.tunnel_established:
                    self.tunnel_established = True
                self.communication_channel = knx_msg.body.get('communication_channel_id')
                self.knx_source_address = knx_msg.body.get('data_block').get('knx_address')
                self.future.set_result(True)
            else:
                LOGGER.error(knx_msg.ERROR)
                self.transport.close()
                self.future.set_result(None)
        elif isinstance(knx_msg, KnxConnectionStateResponse):
            # After receiving a CONNECTIONSTATE_RESPONSE schedule the next one
            self.loop.call_later(50, self.knx_keep_alive)
        elif isinstance(knx_msg, KnxDisconnectRequest):
            disconnect_response = KnxDisconnectResponse(communication_channel=self.communication_channel)
            self.transport.sendto(disconnect_response.get_message())
            self.transport.close()
            if not self.future.done():
                self.future.set_result(None)
        elif isinstance(knx_msg, KnxDisconnectResponse):
            self.transport.close()
            if not self.future.done():
                self.future.set_result(None)
        else:
            LOGGER.error('Unknown Core Message: {}'.format(knx_msg.header.get('service_type')))

    def handle_configuration_services(self, knx_msg):
        if isinstance(knx_msg, KnxDeviceConfigurationRequest):
            conf_ack = KnxDeviceConfigurationAck(
                communication_channel=knx_msg.body.get('communication_channel_id'),
                sequence_count=knx_msg.body.get('sequence_counter'))
            self.transport.sendto(conf_ack.get_message())
        else:
            LOGGER.error('Unknown Configuration Message: {}'.format(knx_msg.header.get('service_type')))

    def handle_tunnel_services(self, knx_msg):
        if isinstance(knx_msg, KnxTunnellingRequest):
            knx_src = knx_msg.parse_knx_address(knx_msg.body.get('cemi').get('knx_source'))
            knx_dst = knx_msg.parse_knx_address(knx_msg.body.get('cemi').get('knx_destination'))
            cemi_msg_code = knx_msg.body.get('cemi').get('message_code')
            cemi_tpci_type = knx_msg.body.get('cemi').get('tpci').get('type')
            cemi_apci_type = None
            if knx_msg.body.get('cemi').get('apci'):
                cemi_apci_type = knx_msg.body.get('cemi').get('apci').get('type')

            LOGGER.debug(('[KnxTunnellingRequest] SRC: {knx_src}, DST: {knx_dst}, CODE: {msg_code}, '
                          'SEQ: {seq}. TPCI: {tpci}, APCI: {apci}').format(
                knx_src=knx_src,
                knx_dst=knx_dst,
                msg_code=_CEMI_MSG_CODES.get(cemi_msg_code),
                seq=knx_msg.body.get('cemi').get('tpci').get('sequence'),
                tpci=_CEMI_TPCI_TYPES.get(cemi_tpci_type),
                apci=_CEMI_APCI_TYPES.get(cemi_apci_type)))

            if cemi_msg_code == CEMI_MSG_CODES.get('L_Data.con'):
                # TODO: is this for NCD's even necessary?
                if cemi_tpci_type in [CEMI_TPCI_TYPES.get('UCD'), CEMI_TPCI_TYPES.get('NCD')]:
                    # This could be e.g. a response for a tcpi_connect() or
                    # tpci_send_ncd() message. For these messages the return
                    # value should be boolean to indicate that either a
                    # address is not in use/device is not available (UCD)
                    # or an error happened (NCD).
                    if knx_msg.body.get('cemi').get('controlfield_1').get('confirm'):
                        # If the confirm flag is set, the device is not alive
                        self.process_target(knx_dst, False, knx_msg)
                    else:
                        # If the confirm flag is not set, the device is alive
                        self.process_target(knx_dst, True, knx_msg)

                        if cemi_tpci_type == CEMI_TPCI_TYPES.get('UCD'):
                            # For each alive device, create a new sequence counter
                            self.tpci_seq_counts[knx_dst] = 0

                elif cemi_tpci_type == CEMI_TPCI_TYPES.get('NDP'):
                    # If we get a confirmation for our device descriptor request,
                    # check if L_Data.ind arrives.
                    if cemi_apci_type in [CEMI_APCI_TYPES.get('A_DeviceDescriptor_Read'),
                                          CEMI_APCI_TYPES.get('A_PropertyValue_Read')]:
                        self.loop.call_later(3, self.process_target, knx_dst, False, knx_msg)

                elif cemi_tpci_type == CEMI_TPCI_TYPES.get('UDP'):
                    # After e.g. an A_GroupValue_Write we just get a
                    # L_Data.con for a UDP.
                    if knx_dst in self.target_futures.keys() and \
                            not self.target_futures[knx_dst].done():
                        self.target_futures[knx_dst].set_result(False)
                        del self.target_futures[knx_dst]
                    else:
                        self.response_queue.append(knx_msg)

            elif cemi_msg_code == CEMI_MSG_CODES.get('L_Data.ind'):

                if cemi_tpci_type == CEMI_TPCI_TYPES.get('UCD'):

                    if knx_msg.body.get('cemi').get('tpci').get('status') is 1:
                        # TODO: why checking status here? pls document why
                        if knx_dst in self.target_futures.keys():
                            if not self.target_futures[knx_dst].done():
                                self.target_futures[knx_dst].set_result(False)
                                del self.target_futures[knx_dst]
                        else:
                            self.response_queue.append(knx_msg)

                elif cemi_tpci_type == CEMI_TPCI_TYPES.get('NCD'):
                    # If we sent e.g. a A_DeviceDescriptor_Read, this
                    # would arrive right before the actual data.
                    # TODO: if something fails, can we see it in this message?
                    pass

                elif cemi_tpci_type == CEMI_TPCI_TYPES.get('NDP'):

                    if cemi_apci_type == CEMI_APCI_TYPES.get('A_DeviceDescriptor_Response'):
                        LOGGER.debug('{knx_src}: DEVICEDESCRIPTOR_RESPONSE DATA: {data}'.format(
                            knx_src=knx_src,
                            data=knx_msg.body.get('cemi').get('data')))

                    elif cemi_apci_type == CEMI_APCI_TYPES.get('A_Authorize_Response'):
                        LOGGER.debug('{knx_src}: AUTHORIZE_RESPONSE DATA: {data}'.format(
                            knx_src=knx_src,
                            data=knx_msg.body.get('cemi').get('data')))

                    elif cemi_apci_type == CEMI_APCI_TYPES.get('A_PropertyValue_Response'):
                        LOGGER.debug('{peer}/{knx_source}/{knx_dest}: PROPERTY_VALUE_RESPONSE DATA: {data}'.format(
                            peer=self.peername[0],
                            knx_source=knx_src,
                            knx_dest=knx_dst,
                            data=knx_msg.body.get('cemi').get('data')[4:]))

                    elif cemi_apci_type == CEMI_APCI_TYPES.get('A_Memory_Response'):
                        LOGGER.debug('{peer}/{knx_src}: MEMORY_RESPONSE DATA: {data}'.format(
                            peer=self.peername[0],
                            knx_src=knx_src,
                            data=knx_msg.body.get('cemi').get('data')))

                    # If we receive any Numbered Data Packets for
                    # targets without futures, add the knx_source
                    # to the response queue for later processing.
                    self.process_target(knx_src, knx_msg)

            # If we receive any L_Data.con or L_Data.ind from a KNXnet/IP gateway
            # we have to reply with a tunnelling ack.
            if cemi_msg_code in [CEMI_MSG_CODES.get('L_Data.con'), CEMI_MSG_CODES.get('L_Data.ind')]:
                tunnelling_ack = KnxTunnellingAck(
                    communication_channel=knx_msg.body.get('communication_channel_id'),
                    sequence_count=knx_msg.body.get('sequence_counter'))
                self.transport.sendto(tunnelling_ack.get_message())

        elif isinstance(knx_msg, KnxTunnellingAck):
            # TODO: do we have to increase any sequence here?
            LOGGER.debug('Tunnelling ACK reqceived')
        else:
            LOGGER.error('Unknown Tunnelling Message: {}'.format(knx_msg.header.get('service_type')))

    def send_data(self, data, target=None):
        """A wrapper for sendto() that takes care of incrementing the sequence counter.

        Note: the sequence counter field is only 1 byte. After incrementing the counter
        to 255, it seems to be OK to just start over from 0. At least this applies
        to the tested devices."""
        f = asyncio.Future()
        if target:
            self.target_futures[target] = f
        self.transport.sendto(data)
        if self.sequence_count == 255:
            self.sequence_count = 0
        else:
            self.sequence_count += 1
        return f

    def tpci_connect(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.tpci_unnumbered_control_data('CONNECT')
        return self.send_data(tunnel_request.get_message(), target)

    def tpci_disconnect(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.tpci_unnumbered_control_data('DISCONNECT')
        return self.send_data(tunnel_request.get_message(), target)

    def tpci_send_ncd(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.tpci_numbered_control_data('ACK', sequence=self.tpci_seq_counts.get(target))
        # increment TPCI sequence counter
        if self.tpci_seq_counts.get(target) == 15:
            self.tpci_seq_counts[target] = 0
        else:
            self.tpci_seq_counts[target] += 1
        return self.send_data(tunnel_request.get_message(), target)

    def make_tunnel_request(self, knx_dst):
        """A helper function that returns a KnxTunnellingRequest that is already predefined
        for the current tunnel connection. It already sets the communication channel, the
        sequence count, the KNX source address and the peer which are all handled by the
        protocol instance anyway."""
        tunnel_request = KnxTunnellingRequest(
            communication_channel=self.communication_channel,
            sequence_count=self.sequence_count,
            knx_source=self.knx_source_address,
            knx_destination=knx_dst)
        tunnel_request.set_peer(self.transport.get_extra_info('sockname'))
        return tunnel_request

    def make_configuration_request(self):
        conf_request = KnxDeviceConfigurationRequest(
            sockname=self.transport.get_extra_info('sockname'),
            communication_channel=self.communication_channel,
            sequence_count=self.sequence_count)
        # conf_request.set_peer(self.transport.get_extra_info('sockname'))
        return conf_request

    def knx_keep_alive(self):
        """Sending CONNECTIONSTATE_REQUESTS periodically to
        keep the tunnel alive."""
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
        tunnel_request.tpci_unnumbered_control_data('DISCONNECT')
        self.transport.sendto(tunnel_request.get_message())

    @asyncio.coroutine
    def apci_device_descriptor_read(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_device_descriptor_read(
            sequence=self.tpci_seq_counts.get(target))
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest):
            cemi = value.body.get('cemi')
            if cemi.get('apci').get('type') == CEMI_APCI_TYPES.get('A_DeviceDescriptor_Response') and \
                    cemi.get('data'):
                return value.body.get('cemi').get('data')
        else:
            return False

    @asyncio.coroutine
    def apci_property_value_read(self, target, object_index=0, property_id=0x0f,
                                 num_elements=1, start_index=1):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_property_value_read(
            sequence=self.tpci_seq_counts.get(target),
            object_index=object_index,
            property_id=property_id,
            num_elements=num_elements,
            start_index=start_index)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.body.get('cemi').get('data'):
            return value.body.get('cemi').get('data')[4:]
        else:
            return False

    @asyncio.coroutine
    def apci_property_description_read(self, target, object_index=0, property_id=0x0f,
                                       num_elements=1, start_index=1):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_property_description_read(
            sequence=self.tpci_seq_counts.get(target),
            object_index=object_index,
            property_id=property_id,
            num_elements=num_elements,
            start_index=start_index)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.body.get('cemi').get('data'):
            return value.body.get('cemi').get('data')[4:]
        else:
            return False

    @asyncio.coroutine
    def apci_memory_read(self, target, memory_address=0x0060, read_count=1):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_memory_read(
            sequence=self.tpci_seq_counts.get(target),
            memory_address=memory_address,
            read_count=read_count)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.body.get('cemi').get('data'):
            return value.body.get('cemi').get('data')[2:]
        else:
            return False

    @asyncio.coroutine
    def apci_memory_write(self, target, memory_address=0x0060, write_count=1,
                          data=b'\x00'):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_memory_write(
            sequence=self.tpci_seq_counts.get(target),
            memory_address=memory_address,
            write_count=write_count,
            data=data)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.body.get('cemi').get('data'):
            return value.body.get('cemi').get('data')[2:]
        else:
            return False

    @asyncio.coroutine
    def apci_authenticate(self, target, key=0xffffffff):
        """Send an A_Authorize_Request to target with the
        supplied key. Returns the access level as an int
        or False if an error occurred."""
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_authorize_request(
            sequence=self.tpci_seq_counts.get(target),
            key=key)
        auth = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(auth, KnxTunnellingRequest):
            return int.from_bytes(auth.body.get('cemi').get('data'), 'big')
        else:
            return False

    @asyncio.coroutine
    def apci_group_value_write(self, target, value=0):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_group_value_write(value=value)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.body.get('cemi').get('data'):
            return value.body.get('cemi').get('data')[4:]
        else:
            return False

    @asyncio.coroutine
    def apci_individual_address_read(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_individual_address_read(
            sequence=self.tpci_seq_counts.get(target))
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.body.get('cemi').get('data'):
            return value.body.get('cemi').get('data')[4:]
        else:
            return False

    @asyncio.coroutine
    def apci_user_manufacturer_info_read(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_user_manufacturer_info_read(
            sequence=self.tpci_seq_counts.get(target))
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.body.get('cemi').get('data'):
            return value.body.get('cemi').get('data')[4:]
        else:
            return False