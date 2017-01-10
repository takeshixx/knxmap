"""Device Management Services"""
import io
import struct
import logging

from knxmap import KNX_MESSAGE_TYPES, PARAMETER_OBJECTS
from knxmap.messages.main import KnxMessage

LOGGER = logging.getLogger(__name__)


class KnxDeviceConfigurationRequest(KnxMessage):
    # TODO: properly implement configuration requests

    def __init__(self, message=None, sockname=None, communication_channel=None,
                 sequence_count=0, message_code=0xfc, cemi_ndpu_len=1):
        super(KnxDeviceConfigurationRequest, self).__init__()
        if message:
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('DEVICE_CONFIGURATION_REQUEST')
            self.communication_channel = communication_channel
            self.sequence_count = sequence_count
            self.cemi_message_code = message_code
            self.cemi_npdu_len = cemi_ndpu_len
            try:
                self.source, self.port = sockname
                self.pack_knx_message()
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self, cemi=None):
        self.body = bytearray(struct.pack('!B', 4))  # structure_length
        self.body.extend(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', self.sequence_count))  # sequence counter
        self.body.extend(struct.pack('!B', 0))  # reserved
        # cEMI
        # if cemi:
        #    self.body += cemi
        # else:
        #    self.body += self._pack_cemi()

        self.body.extend(struct.pack('!B', self.cemi_message_code))  # M_PropRead.req
        # self.body += struct.pack('!B', CEMI_MESSAGE_CODES.get('L_Data.req'))
        self.body.extend(struct.pack('!H', 11))
        self.body.extend(struct.pack('!B', 11))
        self.body.extend(struct.pack('!B', PARAMETER_OBJECTS.get('PID_ADDITIONAL_INDIVIDUAL_ADDRESSES')))
        # self.body += struct.pack('!B', DEVICE_OBJECTS.get('PID_SERIAL_NUMBER'))
        # self.body += struct.pack('!H', 0x1001)
        self.body.extend(struct.pack('!B', 0x10))
        self.body.extend(struct.pack('!B', 0x00))
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['sequence_counter'] = self._unpack_stream('!B', message)
            self.body['reserved'] = self._unpack_stream('!B', message)
            # cEMI
            # self.body['cemi'] = self._unpack_cemi(message)
            self.body['the_end'] = message.read()
        except Exception as e:
            LOGGER.exception(e)


class KnxDeviceConfigurationAck(KnxMessage):
    def __init__(self, message=None, communication_channel=None, sequence_count=0):
        super(KnxDeviceConfigurationAck, self).__init__()
        if message:
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
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['sequence_counter'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)
        except Exception as e:
            LOGGER.exception(e)