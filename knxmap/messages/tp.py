"""Twited Pair protocol"""
import struct
import logging

from knxmap.data.constants import (TPCI_NUMBERED_CONTROL_DATA_TYPES,
                                   TPCI_UNNUMBERED_CONTROL_DATA_TYPES,
                                   CEMI_APCI_TYPES, CEMI_TPCI_TYPES)
import knxmap.utils
from .tpci import Tpci
from .apci import Apci

LOGGER = logging.getLogger(__name__)


class DataRequest(object):
    # control byte
    # source adddress
    #
    # destination address
    #
    # npci
    # tpci/apci
    # apci (optional)
    # data (optional)
    # checksum
    def __init__(self, knx_source=None, knx_destination=None, routing_count=6,
                 data=None, destination_type=0, tpci_type=None, tpci_sequence=0,
                 apci_type=None, apci_data=None, message=None, tpci_control_type=None):
        self.control_field = None
        self.npci = None
        self.tpci = None
        self.apci = None
        self.knx_source = knx_source
        self.knx_destination = knx_destination
        self.routing_count = routing_count
        self.destination_type = destination_type
        self.tpci_type = tpci_type
        self.tpci_sequence = tpci_sequence
        self.tpci_control_type = tpci_control_type
        self.apci_type = apci_type
        self.apci_data = apci_data
        self.data = data or bytearray()
        if message:
            self.unpack(message)
        else:
            assert isinstance(knx_source, int), 'KNX source invalid %s' % knx_source
            assert isinstance(knx_destination, int), 'KNX destination invalid %s' % knx_destination

    def __repr__(self):
        return '%s knx_source: %s, knx_destination: %s, tpci_type: %s, apci_type: %s, ' \
               'destination_type: %s' % (
            self.__class__.__name__,
            knxmap.utils.parse_knx_address(self.knx_source),
            knxmap.utils.parse_knx_address(self.knx_destination),
            CEMI_TPCI_TYPES.get(self.tpci_type),
            CEMI_APCI_TYPES.get(self.apci_type),
            self.npci.get('destination_type'))

    @staticmethod
    def _unpack_stream(fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            LOGGER.exception(e)

    @staticmethod
    def pack_control_field(priority=0x00, repeat_flag=False):
        """Pack control field"""
        cf = 0
        cf |= 0 << 0
        cf |= 0 << 1
        cf |= priority << 2
        cf |= 0 << 4
        cf |= (1 if repeat_flag else 0) << 5
        cf |= 0 << 6
        cf |= 0 << 7
        return cf

    @staticmethod
    def unpack_control_field(data):
        """Parse controlfield1 to a dict."""
        cf = {}
        cf['priority'] = 0
        cf['priority'] |= ((data >> 2) & 1) << 0
        cf['priority'] |= ((data >> 3) & 1) << 1
        cf['repeat_flag'] = (data >> 5) & 1
        return cf

    @staticmethod
    def pack_npci(data_len=0, routing_count=6, destination_type=0):
        # NOTE: routing_count=7 will disable routing count.
        npci = 0
        npci |= data_len << 0
        npci |= routing_count << 4
        npci |= (1 if destination_type else 0) << 7
        return npci

    @staticmethod
    def unpack_npci(data):
        """Parse NPCI to a dict."""
        npci = {}
        npci['data_length'] = 0
        npci['data_length'] |= ((data >> 0) & 1) << 0
        npci['data_length'] |= ((data >> 1) & 1) << 1
        npci['data_length'] |= ((data >> 2) & 1) << 2
        npci['data_length'] |= ((data >> 3) & 1) << 3
        npci['routing_count'] = 0
        npci['routing_count'] |= ((data >> 4) & 1) << 0
        npci['routing_count'] |= ((data >> 5) & 1) << 1
        npci['routing_count'] |= ((data >> 6) & 1) << 2
        npci['destination_type'] = ((data >> 7) & 1) << 0
        return npci

    def checksum(self, data):
        checksum = data[0]
        for i in data[1:]:
            checksum ^= i
        return checksum

    def pack(self):
        #data_request = bytearray(struct.pack('!B', self.pack_control_field()))
        # TODO: fix
        data_request = bytearray(struct.pack('!B', 0xb0))
        data_request.extend(struct.pack('!H', self.knx_source))
        data_request.extend(struct.pack('!H', self.knx_destination))
        tpci = None
        data_len = 0
        if self.data:
            data_len = len(self.data)
        if self.apci_type:
            data_len += 1
        data_request.extend(struct.pack('!B', self.pack_npci(data_len=data_len,
                                                             destination_type=self.destination_type)))
        if self.tpci_type:
            tpci = Tpci(tpci_type=self.tpci_type,
                        tpci_sequence=self.tpci_sequence)
            tpci = tpci.pack()
            if self.tpci_type == 'UCD':
                tpci |= TPCI_UNNUMBERED_CONTROL_DATA_TYPES.get(self.tpci_control_type) << 0
            elif self.tpci_type == 'NCD':
                tpci |= TPCI_NUMBERED_CONTROL_DATA_TYPES.get(self.tpci_control_type) << 0
        if self.apci_type is not None:
            apci = Apci(apci_type=self.apci_type,
                        apci_data=self.apci_data)
            apci = apci.pack()
            apci |= ((tpci >> 2) & 1) << 10
            apci |= ((tpci >> 3) & 1) << 11
            apci |= ((tpci >> 4) & 1) << 12
            apci |= ((tpci >> 5) & 1) << 13
            apci |= ((tpci >> 6) & 1) << 14
            apci |= ((tpci >> 7) & 1) << 15
            data_request.extend(struct.pack('!H', apci))
            if self.data:
                data_request.extend(self.data)
        elif tpci:
            data_request.extend(struct.pack('<B', tpci))
        return data_request

    def unpack(self, message):
        self.control_field = self.unpack_control_field(self._unpack_stream('!B', message))
        self.knx_source = self._unpack_stream('!H', message)
        self.knx_destination = self._unpack_stream('!H', message)
        #self.npci = self.unpack_npci(self._unpack_stream('!B', message))
        _npci = self._unpack_stream('!B', message)
        self.npci = self.unpack_npci(_npci)
        if self.npci.get('data_length') > 0:
            tpci_apci = bytearray(self._unpack_stream('{}s'.format(self.npci.get('data_length')),
                                                      message))
            self.tpci = Tpci()
            self.tpci.unpack(tpci_apci[0])
            self.tpci_type = self.tpci.tpci_type
            self.apci = Apci()
            self.apci.unpack(tpci_apci)
            self.apci_type = self.apci.apci_type
            if self.npci.get('data_length') > 1:
                self.data = message.read()


class ExtendedDataRequest(object):
    # control byte
    # extended control byte
    # source adddress
    #
    # destination address
    #
    # data length
    # tpci/apci
    # apci (optional)
    # data (optional)
    # checksum
    def __init__(self, knx_source=None, knx_destination=None, routing_count=6,
                 data=None, destination_type=0, tpci_type=None, tpci_sequence=0,
                 apci_type=None, apci_data=None, message=None, tpci_control_type=None):
        self.control_field = None
        self.extended_control_field = None
        self.npci = None
        self.tcpi = None
        self.apci = None
        self.knx_source = knx_source
        self.knx_destination = knx_destination
        self.routing_count = routing_count
        self.destination_type = destination_type
        self.tpci_type = tpci_type
        self.tpci_sequence = tpci_sequence
        self.tpci_control_type = tpci_control_type
        self.apci_type = apci_type
        self.apci_data = apci_data
        self.data = data or bytearray()
        if message:
            self.unpack(message)
        else:
            assert isinstance(knx_source, int)
            assert isinstance(knx_destination, int)
            if tpci_type:
                assert tpci_type in CEMI_TPCI_TYPES.keys(),\
                    'Invalid TPCI type %s' % tpci_type
            if tpci_control_type:
                assert tpci_control_type in TPCI_UNNUMBERED_CONTROL_DATA_TYPES.keys() or \
                       tpci_control_type in TPCI_NUMBERED_CONTROL_DATA_TYPES.keys(), \
                            'Invalid UCD type %s' % tpci_control_type
            if apci_type:
                assert apci_type in CEMI_APCI_TYPES.keys(),\
                    'Invalid APCI type %s' % apci_type

    def __repr__(self):
        return '%s knx_source: %s, knx_destination: %s, tpci_type: %s, apci_type: %s' % (
            self.__class__.__name__,
            knxmap.utils.parse_knx_address(self.knx_source),
            knxmap.utils.parse_knx_address(self.knx_destination),
            CEMI_TPCI_TYPES.get(self.tpci_type),
            CEMI_APCI_TYPES.get(self.apci_type))

    @staticmethod
    def _unpack_stream(fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            LOGGER.exception(e)

    @staticmethod
    def pack_control_field(confirm=False, acknowledge_req=False, priority=0x00,
                           system_broadcast=True, repeat_flag=True, frame_type=True):
        """Pack controlfield1 of the cEMI message.

          Bit  |
         ------+---------------------------------------------------------------
           7   | Frame Type  - 0x0 for extended frame
               |               0x1 for standard frame
         ------+---------------------------------------------------------------
           6   | Reserved
               |
         ------+---------------------------------------------------------------
           5   | Repeat Flag - 0x0 repeat frame on medium in case of an error
               |               0x1 do not repeat
         ------+---------------------------------------------------------------
           4   | System Broadcast - 0x0 system broadcast
               |                    0x1 broadcast
         ------+---------------------------------------------------------------
           3   | Priority    - 0x0 system
               |               0x1 normal
         ------+               0x2 urgent
           2   |               0x3 low
               |
         ------+---------------------------------------------------------------
           1   | Acknowledge Request - 0x0 no ACK requested
               | (L_Data.req)          0x1 ACK requested
         ------+---------------------------------------------------------------
           0   | Confirm      - 0x0 no error
               | (L_Data.con) - 0x1 error
         ------+---------------------------------------------------------------"""
        cf = 0
        cf |= (1 if confirm else 0) << 0
        cf |= (1 if acknowledge_req else 0) << 1
        cf |= priority << 2
        cf |= (1 if system_broadcast else 0) << 4
        cf |= (1 if repeat_flag else 0) << 5
        cf |= 0 << 6  # reserved
        cf |= (1 if frame_type else 0) << 7
        return cf

    @staticmethod
    def unpack_control_field(data):
        """Parse controlfield1 to a dict."""
        cf = {}
        cf['confirm'] = (data >> 0) & 1
        cf['acknowledge_req'] = (data >> 1) & 1
        cf['priority'] = 0
        cf['priority'] |= ((data >> 2) & 1) << 0
        cf['priority'] |= ((data >> 3) & 1) << 1
        cf['system_broadcast'] = (data >> 4) & 1
        cf['repeat_flag'] = (data >> 5) & 1
        cf['reserved'] = (data >> 6) & 1
        cf['frame_type'] = (data >> 7) & 1
        return cf

    @staticmethod
    def pack_extended_control_field(ext_frame_format=0x00, hop_count=6, address_type=0):
        """Pack controlfield2 of the cEMI message.

          Bit  |
         ------+---------------------------------------------------------------
           7   | Destination Address Type - 0x0 individual address
               |                          - 0x1 group address
         ------+---------------------------------------------------------------
          6-4  | Hop Count (0-7)
         ------+---------------------------------------------------------------
          3-0  | Extended Frame Format - 0x0 standard frame
         ------+---------------------------------------------------------------"""
        cf = 0
        cf |= ext_frame_format << 0
        cf |= hop_count << 4
        cf |= address_type << 7
        return cf

    @staticmethod
    def unpack_extended_control_field(data):
        """Parse controlfield2 to a dict."""
        cf = {}
        cf['ext_frame_format'] = 0
        cf['ext_frame_format'] |= ((data >> 0) & 1) << 0
        cf['ext_frame_format'] |= ((data >> 1) & 1) << 1
        cf['ext_frame_format'] |= ((data >> 2) & 1) << 2
        cf['ext_frame_format'] |= ((data >> 3) & 1) << 3
        cf['hop_count'] = 0
        cf['hop_count'] |= ((data >> 4) & 1) << 0
        cf['hop_count'] |= ((data >> 5) & 1) << 1
        cf['hop_count'] |= ((data >> 6) & 1) << 2
        cf['address_type'] = (data >> 7) & 1
        return cf

    def checksum(self, data):
        checksum = data[0]
        for i in data[1:]:
            checksum ^= i
        return checksum

    def pack(self):
        data_request = bytearray(struct.pack('!B', self.pack_control_field()))
        data_request.extend(struct.pack('!B', self.pack_extended_control_field(
            hop_count=self.routing_count,
            address_type=self.destination_type)))
        data_request.extend(struct.pack('!H', self.knx_source))
        data_request.extend(struct.pack('!H', self.knx_destination))
        data_len = 0
        if self.data:
            data_len = len(self.data)
        if self.apci_type:
            data_len += 1
        data_request.extend(struct.pack('!B', data_len))
        if self.tpci_type:
            tpci = Tpci(tpci_type=self.tpci_type,
                        tpci_sequence=self.tpci_sequence)
            tpci = tpci.pack()
            if self.tpci_type == 'UCD':
                tpci |= TPCI_UNNUMBERED_CONTROL_DATA_TYPES.get(self.tpci_control_type) << 0
            elif self.tpci_type == 'NCD':
                tpci |= TPCI_NUMBERED_CONTROL_DATA_TYPES.get(self.tpci_control_type) << 0
        if self.apci_type:
            apci = Apci(apci_type=self.apci_type,
                        apci_data=self.apci_data)
            apci = apci.pack()
            apci |= ((tpci >> 2) & 1) << 10
            apci |= ((tpci >> 3) & 1) << 11
            apci |= ((tpci >> 4) & 1) << 12
            apci |= ((tpci >> 5) & 1) << 13
            apci |= ((tpci >> 6) & 1) << 14
            apci |= ((tpci >> 7) & 1) << 15
            data_request.extend(struct.pack('!H', apci))
        else:
            data_request.extend(struct.pack('<H', tpci))
        if self.data:
            data_request.extend(self.data)
        # TODO: do we need this checksum?
        #data_request.extend(struct.pack('!B', self.checksum(data_request)))
        return data_request

    def unpack(self, message):
        self.control_field = self.unpack_control_field(
            self._unpack_stream('!B', message))
        self.extended_control_field = self.unpack_extended_control_field(
            self._unpack_stream('!B', message))
        self.knx_source = self._unpack_stream('!H', message)
        self.knx_destination = self._unpack_stream('!H', message)
        self.npdu_len = self._unpack_stream('!B', message)
        tpci_apci = bytearray(self._unpack_stream('{}s'.format(self.npdu_len + 1),
                                                  message))
        self.tpci = Tpci()
        self.tpci.unpack(tpci_apci[0])
        self.tpci_type = self.tpci.tpci_type
        self.apci = Apci()
        self.apci.unpack(tpci_apci)
        self.apci_type = self.apci.apci_type
        if self.npdu_len > 1:
            self.data = tpci_apci[2:]


class PollDataRequest(object):
    # control byte
    # source adddress
    #
    # destination address
    #
    # polling counter
    # checksum
    def __init__(self):
        pass
