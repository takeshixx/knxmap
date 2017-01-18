"""Remote Diagnostics and Configuration"""
import io
import struct
import logging

from knxmap import KNX_MESSAGE_TYPES, _LAYER_TYPES, KNX_STATUS_CODES
from .main import KnxMessage

LOGGER = logging.getLogger(__name__)


class KnxRemoteDiagnosticRequest(KnxMessage):
    def __init__(self, message=None, sockname=None):
        super(KnxRemoteDiagnosticRequest, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('REMOTE_DIAGNOSTIC_REQUEST')
            try:
                self.source, self.port = sockname
                self.pack_knx_message()
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self):
        #self.body = self._pack_hpai()
        # selector
        import socket
        hpai = bytearray(struct.pack('!B', 8))  # structure_length
        hpai.extend(struct.pack('!B', 0x01))  # protocol code
        hpai.extend(socket.inet_aton(self.source))
        hpai.extend(struct.pack('!H', self.port))
        #hpai.extend(struct.pack('!B', 0x02)) # structure length
        #hpai.extend(struct.pack('!B', 0x01)) # programming mode selector
        hpai.extend(struct.pack('!B', 0x08)) # structure length
        hpai.extend(struct.pack('!B', 0x02)) # programming mode selector
        hpai.extend(struct.pack('!B', 0x00))
        hpai.extend(struct.pack('!B', 0x00))
        hpai.extend(struct.pack('!B', 0x54))
        hpai.extend(struct.pack('!B', 0xff))
        hpai.extend(struct.pack('!B', 0xa0))
        hpai.extend(struct.pack('!B', 0x52))
        return hpai
        #return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body = self._unpack_hpai(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxRemoteDiagnosticResponse(KnxMessage):
    def __init__(self, message=None):
        super(KnxRemoteDiagnosticResponse, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('REMOTE_DIAGNOSTIC_RESPONSE')
            self.pack_knx_message()

    def _pack_knx_body(self):
        raise NotImplementedError

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body = self._unpack_hpai(message)
            self.dib_dev_info = self._unpack_dib_dev_info(message)
            self.dib_supp_sv_families = self._unpack_dib_supp_sv_families(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxRemoteBasicConfigurationRequest(KnxMessage):
    pass


class KnxRemoteResetRequest(KnxMessage):
    pass
