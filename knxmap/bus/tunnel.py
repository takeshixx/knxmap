import asyncio
import logging
import struct

import knxmap.utils
from knxmap.data.constants import *
from knxmap.exceptions import *
from knxmap.messages import parse_message, KnxMessage, KnxConnectRequest, KnxConnectResponse, \
                            KnxDisconnectRequest, KnxDisconnectResponse, KnxDeviceConfigurationRequest, \
                            KnxDeviceConfigurationAck, KnxTunnellingRequest, KnxTunnellingAck, \
                            KnxConnectionStateRequest, KnxConnectionStateResponse

LOGGER = logging.getLogger(__name__)


class KnxTunnelConnection(asyncio.DatagramProtocol):
    """Communicate with bus devices via a KNX gateway using TunnellingRequests. A tunneling
    connection is always used if the bus destination is a physical KNX address."""

    def __init__(self, future, connection_type=0x04, layer_type='TUNNEL_LINKLAYER',
                 ndp_defer_time=2, knx_source=None, tunnel_timeout=4, loop=None,
                 nat_mode=False):
        self.future = future
        self.connection_type = connection_type
        self.layer_type = layer_type
        self.target_futures = {}
        self.loop = loop or asyncio.get_event_loop()
        self.transport = None
        self.peername = None
        self.sockname = None
        self.tunnel_established = False
        self.communication_channel = None
        self.sequence_count = 0  # sequence counter in KNX body
        self.tpci_seq_counts = {}  # NCD/NPD counter for each TPCI connection
        self.knx_source_address = knx_source
        self.response_queue = []
        self.ndp_defer_time = ndp_defer_time
        self.tunnel_timeout = tunnel_timeout
        self.nat_mode = nat_mode
        self.wait = None

    def connection_made(self, transport):
        """The connection setup function that takes care of:

        * Sending a KnxConnectRequest
        * Schedule KnxConnectionStateRequests
        * Schedule response queue polling"""
        self.transport = transport
        self.peername = self.transport.get_extra_info('peername')
        if self.nat_mode:
            self.sockname = ('0.0.0.0', 0)
        else:
            self.sockname = self.transport.get_extra_info('sockname')
        connect_request = KnxConnectRequest(
            sockname=self.sockname,
            connection_type=self.connection_type,
            layer_type=self.layer_type)
        LOGGER.trace_outgoing(connect_request)
        self.transport.sendto(connect_request.get_message())
        # Schedule CONNECTIONSTATE_REQUEST to keep the connection alive
        self.loop.call_later(50, self.knx_keep_alive)
        self.loop.call_later(1, self.poll_response_queue)
        self.wait = self.loop.call_later(self.tunnel_timeout,
                                         self.connection_timeout)

    def connection_timeout(self):
        LOGGER.debug('Tunnel connection timed out')
        if self.target_futures:
            for k, v in self.target_futures.items():
                if not v.done():
                    v.set_result(False)
        if self.response_queue:
            for r in self.response_queue:
                try:
                    cemi_msg_code = r.cemi.message_code
                    cemi_tpci_type = r.cemi.tpci.tpci_type
                    cemi_apci_type = None
                    if r.cemi.apci:
                        cemi_apci_type = r.cemi.apci.apci_type
                except AttributeError:
                    continue
        if self.tunnel_established:
            self.knx_tunnel_disconnect()
        self.transport.close()
        if not self.future.done():
            self.future.set_result(None)

    def reset_connection_timeout(self):
        self.wait.cancel()
        self.wait = self.loop.call_later(self.tunnel_timeout,
                                         self.connection_timeout)

    def poll_response_queue(self):
        """Check if there if there is a KNX message for a
        target that arrived out-of-band."""
        if self.response_queue:
            for response in self.response_queue:
                if isinstance(response, bool):
                    self.response_queue.remove(response)
                    continue
                try:
                    src_addr = knxmap.utils.parse_knx_address(response.cemi.knx_source)
                    dst_addr = knxmap.utils.parse_knx_address(response.cemi.knx_destination)
                except AttributeError:
                    src_addr = knxmap.utils.unpack_ip_address(response.source)
                    dst_addr = self.sockname[0]
                if not src_addr and not dst_addr:
                    continue
                if dst_addr in self.target_futures.keys():
                    if not self.target_futures[dst_addr].done():
                        self.target_futures[dst_addr].set_result(response)
                    del self.target_futures[dst_addr]
                elif src_addr in self.target_futures.keys():
                    if not self.target_futures[src_addr].done():
                        self.target_futures[src_addr].set_result(response)
                    del self.target_futures[src_addr]
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
        knx_msg.set_peer(addr)
        LOGGER.trace_incoming(knx_msg)
        knx_service_type = knx_msg.header.get('service_type') >> 8
        if knx_service_type is 0x02:  # Core
            self.handle_core_services(knx_msg)
        elif knx_service_type is 0x03:  # Device Management
            self.handle_configuration_services(knx_msg)
        elif knx_service_type is 0x04:  # Tunnelling
            self.handle_tunnel_services(knx_msg)
        else:
            LOGGER.error('Service not implemented: {}'.format(
                KNX_SERVICES.get(knx_service_type)))
        self.reset_connection_timeout()

    def handle_core_services(self, knx_msg):
        if isinstance(knx_msg, KnxConnectResponse):
            if not knx_msg.ERROR:
                if not self.tunnel_established:
                    self.tunnel_established = True
                self.communication_channel = knx_msg.communication_channel
                if not self.knx_source_address:
                    self.knx_source_address = knx_msg.data_block.get('knx_address')
                self.future.set_result(True)
            else:
                #LOGGER.error('Establishing tunnel connection failed: %s' %
                #             knx_msg.ERROR)
                self.transport.close()
                raise KnxTunnelException(knx_msg.ERROR)
                #self.future.set_result(None)
        elif isinstance(knx_msg, KnxConnectionStateResponse):
            # After receiving a CONNECTIONSTATE_RESPONSE schedule the next one
            self.loop.call_later(50, self.knx_keep_alive)
        elif isinstance(knx_msg, KnxDisconnectRequest):
            disconnect_response = KnxDisconnectResponse(
                communication_channel=self.communication_channel)
            self.transport.sendto(disconnect_response.get_message())
            self.transport.close()
            if not self.future.done():
                self.future.set_result(None)
        elif isinstance(knx_msg, KnxDisconnectResponse):
            self.transport.close()
            if not self.future.done():
                self.future.set_result(None)
        else:
            LOGGER.error('Unknown Core Service message: {}'.format(
                knx_msg.header.get('service_type')))

    def handle_configuration_services(self, knx_msg):
        if isinstance(knx_msg, KnxDeviceConfigurationRequest):
            cemi_msg_code = knx_msg.message_code
            if cemi_msg_code == CEMI_MSG_CODES.get('M_PropRead.con'):
                if knx_msg.num_elements == 0:
                    if knx_msg.data:
                        LOGGER.debug(CEMI_ERROR_CODES.get(knx_msg.data[0]))
                    else:
                        LOGGER.debug('An unknown error occured')
                    self.process_target(knx_msg.source, False, knx_msg)
                else:
                    self.process_target(knx_msg.source, knx_msg)
            conf_ack = KnxDeviceConfigurationAck(
                communication_channel=knx_msg.communication_channel,
                sequence_count=knx_msg.sequence_count)
            LOGGER.trace_outgoing(conf_ack)
            self.transport.sendto(conf_ack.get_message())
        elif isinstance(knx_msg, KnxDeviceConfigurationAck):
            # TODO: is there anything to do with an ACK?
            pass
        else:
            LOGGER.error('Unknown Configuration Servuce message: {}'.format(
                knx_msg.header.get('service_type')))

    def handle_tunnel_services(self, knx_msg):
        if isinstance(knx_msg, KnxTunnellingRequest):
            knx_src = knx_msg.parse_knx_address(knx_msg.cemi.knx_source)
            if knx_msg.cemi.extended_control_field.get('address_type'):
                knx_dst = knx_msg.parse_knx_group_address(knx_msg.cemi.knx_destination)
            else:
                knx_dst = knx_msg.parse_knx_address(knx_msg.cemi.knx_destination)
            cemi_msg_code = knx_msg.cemi.message_code
            cemi_tpci_type = knx_msg.cemi.tpci.tpci_type
            cemi_apci_type = None
            if knx_msg.cemi.apci:
                cemi_apci_type = knx_msg.cemi.apci.apci_type

            if cemi_msg_code == CEMI_MSG_CODES.get('L_Data.con'):
                # TODO: is this for NCD's even necessary?
                if cemi_tpci_type in [CEMI_TPCI_TYPES.get('UCD'),
                                      CEMI_TPCI_TYPES.get('NCD')]:
                    # This could be e.g. a response for a tcpi_connect() or
                    # tpci_send_ncd() message. For these messages the return
                    # value should be boolean to indicate that either a
                    # address is not in use/device is not available (UCD)
                    # or an error happened (NCD).
                    if knx_msg.cemi.control_field.get('confirm'):
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
                        self.loop.call_later(self.ndp_defer_time,
                                             self.process_target,
                                             knx_dst,
                                             False,
                                             knx_msg)
                    elif cemi_apci_type in [CEMI_APCI_TYPES.get('A_Restart'),
                                            CEMI_APCI_TYPES.get('A_Memory_Write')]:
                        self.process_target(knx_dst, True, knx_msg)

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
                    # TODO: will this even happen?
                    # TODO: doesn't it need to use knx_src instead of knx_dst?
                    if knx_msg.cemi.tpci.status is 1:
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
                            data=knx_msg.cemi.data))
                    elif cemi_apci_type == CEMI_APCI_TYPES.get('A_Authorize_Response'):
                        LOGGER.debug('{knx_src}: AUTHORIZE_RESPONSE DATA: {data}'.format(
                            knx_src=knx_src,
                            data=knx_msg.cemi.data))
                    elif cemi_apci_type == CEMI_APCI_TYPES.get('A_PropertyValue_Response'):
                        LOGGER.debug('{peer}/{knx_source}/{knx_dest}: PROPERTY_VALUE_RESPONSE DATA: {data}'.format(
                            peer=self.peername[0],
                            knx_source=knx_src,
                            knx_dest=knx_dst,
                            data=knx_msg.cemi.data[4:]))
                    elif cemi_apci_type == CEMI_APCI_TYPES.get('A_Memory_Response'):
                        LOGGER.debug('{peer}/{knx_src}: MEMORY_RESPONSE DATA: {data}'.format(
                            peer=self.peername[0],
                            knx_src=knx_src,
                            data=knx_msg.cemi.data))

                    # Check if there is still a confirmation packet
                    # left in the queue.
                    for r in self.response_queue:
                        if isinstance(r, KnxTunnellingRequest) and \
                                knx_src == r.parse_knx_address(r.cemi.knx_destination) and \
                                knx_dst == r.parse_knx_address(r.cemi.knx_source) and \
                                r.cemi.message_code == CEMI_MSG_CODES.get('L_Data.con') and \
                                r.cemi.tpci.tpci_type == CEMI_TPCI_TYPES.get('NDP'):
                            self.response_queue.remove(r)

                    # If we receive any Numbered Data Packets for
                    # targets without futures, add the knx_source
                    # to the response queue for later processing.
                    self.process_target(knx_src, knx_msg)

            # If we receive any L_Data.con or L_Data.ind from a KNXnet/IP gateway
            # we have to reply with a tunnelling ack.
            if cemi_msg_code in [CEMI_MSG_CODES.get('L_Data.con'),
                                 CEMI_MSG_CODES.get('L_Data.ind')]:
                tunnelling_ack = KnxTunnellingAck(
                    communication_channel=knx_msg.communication_channel,
                    sequence_count=knx_msg.sequence_counter)
                LOGGER.trace_outgoing(tunnelling_ack)
                self.transport.sendto(tunnelling_ack.get_message())

        elif isinstance(knx_msg, KnxTunnellingAck):
            # TODO: do we have to increase any sequence here?
            LOGGER.debug('Tunnelling ACK reqceived')
            if knx_msg.status:
                LOGGER.error('An error occured during frame transmission')
        else:
            LOGGER.error('Unknown Tunnelling Service message: {}'.format(
                knx_msg.header.get('service_type')))

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
        LOGGER.trace_outgoing(tunnel_request)
        return self.send_data(tunnel_request.get_message(), target)

    def tpci_disconnect(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.tpci_unnumbered_control_data('DISCONNECT')
        LOGGER.trace_outgoing(tunnel_request)
        return self.send_data(tunnel_request.get_message(), target)

    def tpci_send_ncd(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.tpci_numbered_control_data('ACK', sequence=self.tpci_seq_counts.get(target))
        # increment TPCI sequence counter
        if self.tpci_seq_counts.get(target) == 15:
            self.tpci_seq_counts[target] = 0
        else:
            self.tpci_seq_counts[target] += 1
        LOGGER.trace_outgoing(tunnel_request)
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

    def configuration_request(self, target, object_type=0, object_instance=1,
                              property=0, num_elements=1, start_index=1):
        conf_request = KnxDeviceConfigurationRequest(
            sockname=self.transport.get_extra_info('sockname'),
            communication_channel=self.communication_channel,
            sequence_count=self.sequence_count,
            object_type=object_type,
            object_instance=object_instance,
            property=property,
            num_elements=num_elements,
            start_index=start_index)
        LOGGER.trace_outgoing(conf_request)
        return self.send_data(conf_request.get_message(), target[0])

    def knx_keep_alive(self):
        """Sending CONNECTIONSTATE_REQUESTS periodically to
        keep the tunnel alive."""
        connection_state = KnxConnectionStateRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        LOGGER.trace_outgoing(connection_state)
        self.transport.sendto(connection_state.get_message())

    def knx_tunnel_disconnect(self):
        """Close the tunnel connection with a DISCONNECT_REQUEST."""
        disconnect_request = KnxDisconnectRequest(
            sockname=self.sockname,
            communication_channel=self.communication_channel)
        LOGGER.trace_outgoing(disconnect_request)
        self.transport.sendto(disconnect_request.get_message())

    def knx_tpci_disconnect(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.tpci_unnumbered_control_data('DISCONNECT')
        LOGGER.trace_outgoing(tunnel_request)
        self.transport.sendto(tunnel_request.get_message())

    @asyncio.coroutine
    def get_device_type(self, target):
        """A helper function that just returns the device type
        returned by A_DeviceDescriptor_Read as an integer. This
        can be used e.g. to determine whether a type requires
        authorization (System 2/System7) or not (System 1)."""
        descriptor = yield from self.apci_device_descriptor_read(target)
        if not descriptor:
            return False
        try:
            dev_desc = struct.unpack('!H', descriptor)[0]
        except (struct.error, TypeError):
            return False
        _, desc_type, _ = KnxMessage.parse_device_descriptor(dev_desc)
        return desc_type

    @asyncio.coroutine
    def apci_device_descriptor_read(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_device_descriptor_read(
            sequence=self.tpci_seq_counts.get(target))
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest):
            cemi = value.cemi
            if cemi.apci.apci_type == CEMI_APCI_TYPES.get('A_DeviceDescriptor_Response') and \
                    cemi.data:
                return value.cemi.data
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
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.cemi.data:
            return value.cemi.data[4:]
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
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.cemi.data:
            return value.cemi.data[4:]
        else:
            return False

    @asyncio.coroutine
    def apci_memory_read(self, target, memory_address=0x0060, read_count=1):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_memory_read(
            sequence=self.tpci_seq_counts.get(target),
            memory_address=memory_address,
            read_count=read_count)
        LOGGER.trace_outgoing(tunnel_request)
        knx_msg = yield from self.send_data(tunnel_request.get_message(), target)
        # TODO: if that works, it should be implemented for all APCI functions!
        if not isinstance(knx_msg, KnxTunnellingRequest) or \
                knx_msg.cemi.apci.apci_type == CEMI_APCI_TYPES.get('A_Memory_Response') or \
                int.from_bytes(knx_msg.cemi.data[:2], 'big') == memory_address:
            # Put the response back in the queue
            if not isinstance(knx_msg, bool):
                self.response_queue.append(knx_msg)
            yield from asyncio.sleep(.3)
            knx_msg = None
            for response in self.response_queue:
                if isinstance(response, KnxTunnellingRequest) and \
                        response.cemi and response.cemi.apci and \
                        response.cemi.apci.apci_type == CEMI_APCI_TYPES.get('A_Memory_Response') or \
                        int.from_bytes(response.cemi.data[:2], 'big') == memory_address:
                    knx_msg = response
                    self.response_queue.remove(response)
            if not knx_msg:
                LOGGER.debug('No proper response received')
        yield from self.tpci_send_ncd(target)
        if knx_msg and knx_msg.cemi.data:
            return knx_msg.cemi.data[2:]
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
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.cemi.data:
            return value.cemi.data[2:]
        else:
            return False

    @asyncio.coroutine
    def apci_key_write(self, target, level, key):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_key_write(
            sequence=self.tpci_seq_counts.get(target),
            level=level,
            key=key)
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.cemi.data:
            return value.cemi.data[2:]
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
        LOGGER.trace_outgoing(tunnel_request)
        auth = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(auth, KnxTunnellingRequest):
            return int.from_bytes(auth.cemi.data, 'big')
        else:
            return False

    @asyncio.coroutine
    def apci_group_value_write(self, target, value=0):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_group_value_write(value=value)
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.cemi.data:
            return value.cemi.data[4:]
        else:
            return False

    @asyncio.coroutine
    def apci_individual_address_read(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_individual_address_read(
            sequence=self.tpci_seq_counts.get(target))
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.cemi.data:
            return value.cemi.data[4:]
        else:
            return False

    @asyncio.coroutine
    def apci_user_manufacturer_info_read(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_user_manufacturer_info_read(
            sequence=self.tpci_seq_counts.get(target))
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        yield from self.tpci_send_ncd(target)
        if isinstance(value, KnxTunnellingRequest) and \
                value.cemi.data:
            return value.cemi.data[4:]
        else:
            return False

    @asyncio.coroutine
    def apci_restart(self, target):
        tunnel_request = self.make_tunnel_request(target)
        tunnel_request.apci_restart(
            sequence=self.tpci_seq_counts.get(target))
        LOGGER.trace_outgoing(tunnel_request)
        value = yield from self.send_data(tunnel_request.get_message(), target)
        if isinstance(value, KnxTunnellingRequest):
            return True
        else:
            return False
