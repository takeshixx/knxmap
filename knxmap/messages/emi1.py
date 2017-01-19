import io
import struct
import logging

import knxmap.utils
from .tp import DataRequest

LOGGER = logging.getLogger(__name__)


class KnxEmi1Frame(object):
    def __init__(self, data=None, message_code=0x11, knx_source=None,
                 knx_destination=None):
        self.message_code = message_code
        self.knx_source = knxmap.utils.pack_knx_address(knx_source) \
            if isinstance(knx_source, (str, bytes)) else knx_source
        self.knx_destination = knxmap.utils.pack_knx_address(knx_destination) \
            if isinstance(knx_destination, (str, bytes)) else knx_destination
        #self.knx_source = knx_source
        #self.knx_destination = knx_destination
        if data:
            self.unpack(data)

    def __repr__(self):
        return ('EMI1 Frame message_code: {message_code}, source: {source}, '
                'destination: {destination}').format(
            message_code=hex(self.message_code),
            source=knxmap.utils.parse_knx_address(self.knx_source),
            destination=knxmap.utils.parse_knx_address(self.knx_destination))

    @staticmethod
    def _unpack_stream(fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            LOGGER.exception(e)

    def pack(self, message_code=None,):
        message_code = message_code if message_code else self.message_code
        # TODO: do not include message code here?
        #emi = bytearray(struct.pack('!B', message_code))  # message code
        #emi = bytearray(struct.pack('!B', self.message_code))
        emi = bytearray()
        #emi = bytearray(struct.pack('!B', 0x0c))  # EIB/(EMI?) control field
        #emi.extend(struct.pack('!H', self.knx_source or 0x00))  # KNX source address
        #emi.extend(struct.pack('!H', self.knx_destination))  # KNX destination address
        data_request = DataRequest(knx_source=self.knx_source,
                                   knx_destination=self.knx_destination,
                                   tpci_type='UCD',
                                   tpci_control_type='CONNECT')
        emi.extend(data_request.pack())
        return emi

    def unpack(self, data):
        #data = io.BytesIO(data)
        self.message_code = self._unpack_stream('!B', data)
        self.control_field = self._unpack_stream('!B', data)
        self.knx_source = self._unpack_stream('!H', data)
        self.knx_destination = self._unpack_stream('!H', data)

    def pack_data_request(self):
        pass

    def unpack_data_request(self):
        raise NotImplementedError

    @property
    def frame(self):
        return self.pack()

    @frame.setter
    def frame(self, data):
        self.unpack(data)
