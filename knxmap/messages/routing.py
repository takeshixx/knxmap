"""Routing Services"""
import io
import struct
import logging

from knxmap import KNX_MESSAGE_TYPES
from knxmap.messages.main import KnxMessage

LOGGER = logging.getLogger(__name__)


class KnxRoutingIndication(KnxMessage):
    def __init__(self, message=None, knx_source='0.0.0', knx_destination=None):
        super(KnxRoutingIndication, self).__init__()
        if message:
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('ROUTING_INDICATION')
            if knx_source:
                self.set_knx_source(knx_source)
            if knx_destination:
                self.set_knx_destination(knx_destination)

    def _pack_knx_body(self, cemi=None):
        self.body = bytearray()
        if cemi:
            self.body.extend(cemi)
        else:
            self.body.extend(self._pack_cemi())
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['cemi'] = self._unpack_cemi(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxRoutingLostMessage(KnxMessage):
    def __init__(self, message=None):
        super(KnxRoutingLostMessage, self).__init__()
        if message:
            self.unpack_knx_message(message)
        else:
            self.header['service_tye'] = KNX_MESSAGE_TYPES.get('ROUTING_LOST_MESSAGE')
            self.pack_knx_message()

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', 4))  # structure_length
        self.body.extend(struct.pack('!B', 0))  # device state
        self.body.extend(struct.pack('!H', 0))  # number of lost messages
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['device_state'] = self._unpack_stream('!B', message)
            self.body['lost_messages'] = self._unpack_stream('!H', message)
        except Exception as e:
            LOGGER.exception(e)


class KnxRoutingBusy(KnxMessage):
    def __init__(self, message=None):
        super(KnxRoutingBusy, self).__init__()
        if message:
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('ROUTING_BUSY')
            self.pack_knx_message()

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', 4))  # structure_length
        self.body.extend(struct.pack('!B', 0))  # device state
        self.body.extend(struct.pack('!H', 0))  # routing busy wait time
        self.body.extend(struct.pack('!H', 0))  # routing busy control field
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['device_state'] = self._unpack_stream('!B', message)
            self.body['busy_wait_time'] = self._unpack_stream('!H', message)
            self.body['busy_control_field'] = self._unpack_stream('!H', message)
        except Exception as e:
            LOGGER.exception(e)