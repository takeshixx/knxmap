"""Routing Services"""
import io
import struct
import logging

from knxmap import KNX_MESSAGE_TYPES
from .main import KnxMessage
from .cemi import CemiFrame

LOGGER = logging.getLogger(__name__)


class KnxRoutingIndication(KnxMessage):
    def __init__(self, message=None, knx_source='0.0.0', knx_destination=None,
                 message_code=None):
        super(KnxRoutingIndication, self).__init__()
        self.cemi = CemiFrame()
        self.message_code = message_code
        self.additional_info_len = 0
        self.header['service_type'] = KNX_MESSAGE_TYPES.get('ROUTING_INDICATION')
        if knx_source:
            self.set_knx_source(knx_source)
        if knx_destination:
            self.set_knx_destination(knx_destination)
        if message:
            self.message = message
            self.unpack_knx_message(message)

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', self.message_code))
        self.body.extend(struct.pack('!B', self.additional_info_len))
        # TODO: pack rest of cEMI frame
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.message_code = self._unpack_stream('!B', message)
            self.additional_info_len = self._unpack_stream('!B', message)
            #self.cemi = self._unpack_cemi(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxRoutingLostMessage(KnxMessage):
    def __init__(self, message=None):
        super(KnxRoutingLostMessage, self).__init__()
        self.header['service_tye'] = KNX_MESSAGE_TYPES.get('ROUTING_LOST_MESSAGE')
        self.structure_length = 4
        self.device_state = None
        self.lost_messages = 0
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.pack_knx_message()

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', self.structure_length))
        self.body.extend(struct.pack('!B', self.device_state))
        self.body.extend(struct.pack('!H', self.lost_messages))
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.structure_length = self._unpack_stream('!B', message)
            self.device_state = self._unpack_stream('!B', message)
            self.lost_messages = self._unpack_stream('!H', message)
        except Exception as e:
            LOGGER.exception(e)


class KnxRoutingBusy(KnxMessage):
    def __init__(self, message=None):
        super(KnxRoutingBusy, self).__init__()
        self.header['service_type'] = KNX_MESSAGE_TYPES.get('ROUTING_BUSY')
        self.structure_length = 4
        self.device_state = None
        self.busy_wait_time = 0
        self.busy_control_field = 0
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.pack_knx_message()

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', self.structure_length))
        self.body.extend(struct.pack('!B', self.device_state))
        self.body.extend(struct.pack('!H', self.busy_wait_time))
        self.body.extend(struct.pack('!H', self.busy_control_field))
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.structure_length = self._unpack_stream('!B', message)
            self.device_state = self._unpack_stream('!B', message)
            self.busy_wait_time = self._unpack_stream('!H', message)
            self.busy_control_field = self._unpack_stream('!H', message)
        except Exception as e:
            LOGGER.exception(e)
