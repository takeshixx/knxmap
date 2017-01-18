"""Device Management Services"""
import io
import struct
import logging

from knxmap import KNX_MESSAGE_TYPES
from .main import KnxMessage

LOGGER = logging.getLogger(__name__)


class KnxDeviceConfigurationRequest(KnxMessage):
    # TODO: properly implement configuration requests

    def __init__(self, message=None, sockname=None, communication_channel=None,
                 sequence_count=0, message_code=0xfc, object_type=0, object_instance=1,
                 property=0, num_elements=1, start_index=1):
        super(KnxDeviceConfigurationRequest, self).__init__()
        self.header['service_type'] = KNX_MESSAGE_TYPES.get('DEVICE_CONFIGURATION_REQUEST')
        self.communication_channel = communication_channel
        self.sequence_count = sequence_count
        self.message_code = message_code
        self.object_type = object_type
        self.object_instance = object_instance
        self.property = property
        self.num_elements = num_elements
        self.start_index = start_index
        self.data = bytearray()
        try:
            self.source, self.port = sockname
            self.pack_knx_message()
        except TypeError:
            self.source = None
            self.port = None
        if message:
            self.message = message
            self.unpack_knx_message(message)

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', 4))  # structure_length
        self.body.extend(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', self.sequence_count))  # sequence counter
        self.body.extend(struct.pack('!B', 0))  # reserved
        self.body.extend(struct.pack('!B', self.message_code))  # M_PropRead.req
        self.body.extend(struct.pack('!H', self.object_type))
        self.body.extend(struct.pack('!B', self.object_instance))
        self.body.extend(struct.pack('!B', self.property))
        trailer = self.start_index
        trailer |= ((self.num_elements >> 0) & 1) << 12
        trailer |= ((self.num_elements >> 1) & 1) << 13
        trailer |= ((self.num_elements >> 2) & 1) << 14
        trailer |= ((self.num_elements >> 3) & 1) << 15
        self.body.extend(struct.pack('!H', trailer))
        if self.data:
            self.body.extend(self.data)
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.structure_length = self._unpack_stream('!B', message)
            self.communication_channel = self._unpack_stream('!B', message)
            self.sequence_count = self._unpack_stream('!B', message)
            self._unpack_stream('!B', message) # reserved
            self.message_code = self._unpack_stream('!B', message)
            self.object_type = self._unpack_stream('!H', message)
            self.object_instance = self._unpack_stream('!B', message)
            self.property = self._unpack_stream('!B', message)
            trailer = self._unpack_stream('!H', message)
            self.num_elements = 0
            self.num_elements |= ((trailer >> 12) & 1) << 0
            self.num_elements |= ((trailer >> 13) & 1) << 1
            self.num_elements |= ((trailer >> 14) & 1) << 2
            self.num_elements |= ((trailer >> 15) & 1) << 3
            self.start_index = 0
            self.start_index |= ((trailer >> 0) & 1) << 0
            self.start_index |= ((trailer >> 1) & 1) << 1
            self.start_index |= ((trailer >> 2) & 1) << 2
            self.start_index |= ((trailer >> 3) & 1) << 3
            self.start_index |= ((trailer >> 4) & 1) << 4
            self.start_index |= ((trailer >> 5) & 1) << 5
            self.start_index |= ((trailer >> 6) & 1) << 6
            self.start_index |= ((trailer >> 7) & 1) << 7
            self.start_index |= ((trailer >> 8) & 1) << 8
            self.start_index |= ((trailer >> 9) & 1) << 9
            self.start_index |= ((trailer >> 10) & 1) << 10
            self.start_index |= ((trailer >> 11) & 1) << 11
            self.data.extend(message.read())
        except Exception as e:
            LOGGER.exception(e)


class KnxDeviceConfigurationAck(KnxMessage):
    def __init__(self, message=None, communication_channel=None, sequence_count=0):
        super(KnxDeviceConfigurationAck, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('DEVICE_CONFIGURATION_RESPONSE')
            self.communication_channel = communication_channel
            self.sequence_count = sequence_count
            self.pack_knx_message()

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', 4))  # structure_length
        self.body.extend(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', self.sequence_count))  # sequence counter
        self.body.extend(struct.pack('!B', 0))  # status
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.structure_length = self._unpack_stream('!B', message)
            self.communication_channel = self._unpack_stream('!B', message)
            self.sequence_counter = self._unpack_stream('!B', message)
            self.status = self._unpack_stream('!B', message)
        except Exception as e:
            LOGGER.exception(e)
