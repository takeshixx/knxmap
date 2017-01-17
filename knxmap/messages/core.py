"""KNXnet/IP Core Services"""
import io
import struct
import logging

from knxmap import KNX_MESSAGE_TYPES, _LAYER_TYPES, KNX_STATUS_CODES
from .main import KnxMessage

LOGGER = logging.getLogger(__name__)


class KnxSearchRequest(KnxMessage):
    def __init__(self, message=None, sockname=None):
        super(KnxSearchRequest, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('SEARCH_REQUEST')
            try:
                self.source, self.port = sockname
                self.pack_knx_message()
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self):
        self.body = self._pack_hpai()
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body = self._unpack_hpai(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxSearchResponse(KnxMessage):
    def __init__(self, message=None):
        super(KnxSearchResponse, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('SEARCH_RESPONSE')
            self.pack_knx_message()

    def _pack_knx_body(self):
        raise NotImplementedError

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body = self._unpack_hpai(message)
            self.body['dib_dev_info'] = self._unpack_dib_dev_info(message)
            self.body['dib_supp_sv_families'] = self._unpack_dib_supp_sv_families(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxDescriptionRequest(KnxMessage):
    def __init__(self, message=None, sockname=None):
        super(KnxDescriptionRequest, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('DESCRIPTION_REQUEST')
            try:
                self.source, self.port = sockname
                self.pack_knx_message()
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self):
        self.body = self._pack_hpai()
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body = self._unpack_hpai(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxDescriptionResponse(KnxMessage):
    def __init__(self, message=None):
        super(KnxDescriptionResponse, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('DESCRIPTION_RESPONSE')
            self.pack_knx_message()

    def _pack_knx_body(self):
        raise NotImplementedError

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['dib_dev_info'] = self._unpack_dib_dev_info(message)
            self.body['dib_supp_sv_families'] = self._unpack_dib_supp_sv_families(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxConnectRequest(KnxMessage):
    def __init__(self, message=None, sockname=None, layer_type='TUNNEL_LINKLAYER',
                 connection_type=0x04):
        super(KnxConnectRequest, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('CONNECT_REQUEST')
            self.connection_type = connection_type
            self.layer_type = _LAYER_TYPES.get(layer_type)
            try:
                self.source, self.port = sockname
                self.pack_knx_message()
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self):
        # Discovery endpoint
        self.body = self._pack_hpai()
        # Data endpoint
        self.body.extend(self._pack_hpai())
        # Connection request information
        if self.connection_type == 0x04:
            self.body.extend(struct.pack('!B', 4))  # structure_length
        else:
            self.body.extend(struct.pack('!B', 2))  # structure_length
        # TODO: implement other connections (routing, object server)
        self.body.extend(struct.pack('!B', self.connection_type))  # connection type
        if self.connection_type == 0x04:
            self.body.extend(struct.pack('!B', self.layer_type))  # knx layer type
            self.body.extend(struct.pack('!B', 0x00))  # reserved
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            # Discovery endpoint
            self.body = self._unpack_hpai(message)
            # Data endpoint
            self.body['data_endpoint'] = self._unpack_hpai(message)
            # Connection request information
            self.body['connection_request_information'] = {}
            self.body['connection_request_information']['structure_length'] = self._unpack_stream('!B', message)
            self.body['connection_request_information']['connection_type'] = self._unpack_stream('!B', message)
            self.body['connection_request_information']['knx_layer'] = self._unpack_stream('!B', message)
            self.body['connection_request_information']['reserved'] = self._unpack_stream('!B', message)
        except Exception as e:
            LOGGER.exception(e)


class KnxConnectResponse(KnxMessage):
    def __init__(self, message=None):
        super(KnxConnectResponse, self).__init__()
        self.ERROR = None
        self.ERROR_CODE = None
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('CONNECT_RESPONSE')
            self.pack_knx_message()

    def _pack_knx_body(self):
        raise NotImplementedError

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)

            if self.body['status'] != 0x00:
                # TODO: implement some kind of retries and waiting periods
                self.ERROR = KNX_STATUS_CODES[self.body['status']]
                self.ERROR_CODE = self.body['status']
                return

            self.body['hpai'] = self._unpack_hpai(message)
            # Connection response data block
            self.body['data_block'] = {}
            self.body['data_block']['structure_length'] = self._unpack_stream('!B', message)
            self.body['data_block']['connection_type'] = self._unpack_stream('!B', message)
            if self.body['data_block']['connection_type'] == 0x04:
                self.body['data_block']['knx_address'] = super().parse_knx_address(self._unpack_stream('!H', message))
        except Exception as e:
            LOGGER.exception(e)


class KnxConnectionStateRequest(KnxMessage):
    def __init__(self, message=None, sockname=None, communication_channel=None):
        super(KnxConnectionStateRequest, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('CONNECTIONSTATE_REQUEST')
            self.communication_channel = communication_channel
            try:
                self.source, self.port = sockname
                self.pack_knx_message()
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', 0))  # reserved
        # HPAI
        self.body.extend(self._pack_hpai())
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['reserved'] = self._unpack_stream('!B', message)
            # HPAI
            self.body['hpai'] = self._unpack_hpai(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxConnectionStateResponse(KnxMessage):
    def __init__(self, message=None, communication_channel=None):
        super(KnxConnectionStateResponse, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('CONNECTIONSTATE_RESPONSE')
            self.communication_channel = communication_channel
            self.pack_knx_message()

    def _pack_knx_body(self):
        # discovery endpoint
        self.body = bytearray(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', 0))  # status
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)
        except Exception as e:
            LOGGER.exception(e)


class KnxDisconnectRequest(KnxMessage):
    def __init__(self, message=None, sockname=None, communication_channel=None):
        super(KnxDisconnectRequest, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('DISCONNECT_REQUEST')
            self.communication_channel = communication_channel or 0
            try:
                self.source, self.port = sockname
                self.pack_knx_message()
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', 0))  # reserved
        # HPAI
        self.body.extend(self._pack_hpai())
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['reserved'] = self._unpack_stream('!B', message)
            # HPAI
            self.body['hpai'] = self._unpack_hpai(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxDisconnectResponse(KnxMessage):
    def __init__(self, message=None, communication_channel=None):
        super(KnxDisconnectResponse, self).__init__()
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('DISCONNECT_RESPONSE')
            self.communication_channel = communication_channel
            self.pack_knx_message()

    def _pack_knx_body(self):
        # discovery endpoint
        self.body = bytearray(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', 0))  # status
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)
        except Exception as e:
            LOGGER.exception(e)
