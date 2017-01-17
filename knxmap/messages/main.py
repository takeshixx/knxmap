import collections
import logging
import socket
import struct

from knxmap import KNX_CONSTANTS
#from knxmap.messages import CemiFrame
from .cemi import CemiFrame

LOGGER = logging.getLogger(__name__)


class KnxMessage(object):
    header = {
        'header_length': KNX_CONSTANTS['HEADER_SIZE_10'],
        'protocol_version': KNX_CONSTANTS['KNXNETIP_VERSION_10'],
        'service_type': None,
        'total_length': 0}

    def __init__(self):
        self.body = collections.OrderedDict()
        self.message = None
        self.source = None
        self.port = None
        self.knx_source = None
        self.knx_destination = None
        self.message_code = None

    def __repr__(self):
        _repr = '%s source: %s, port: %s' % (
            self.__class__.__name__,
            self.source,
            self.port)
        if self.knx_source:
            _repr += ', knx_source: %s' % KnxMessage.parse_knx_address(self.knx_source)
        if self.knx_destination:
            _repr += ', knx_destination: %s' % KnxMessage.parse_knx_address(self.knx_destination)
        return _repr

    @staticmethod
    def parse_knx_address(address):
        """Parse physical/individual KNX address.

        Address structure (A=Area, L=Line, B=Bus device):
        --------------------
        |AAAA|LLLL|BBBBBBBB|
        --------------------
        4 Bit|4 Bit| 8 Bit

        parse_knx_address(99999)
        '8.6.159'
        """
        assert isinstance(address, int), 'Address should be an integer'
        return '{}.{}.{}'.format((address >> 12) & 0xf, (address >> 8) & 0xf, address & 0xff)

    @staticmethod
    def pack_knx_address(address):
        """Pack physical/individual KNX address.

        pack_knx_address('15.15.255')
        65535
        """
        assert isinstance(address, str), 'Address should be a string'
        parts = address.split('.')
        return (int(parts[0]) << 12) + (int(parts[1]) << 8) + (int(parts[2]))

    @staticmethod
    def parse_knx_group_address(address):
        """Parse KNX group address.

        parse_knx_group_address(12345)
        '6/0/57'
        """
        assert isinstance(address, int), 'Address should be an integer'
        return '{}/{}/{}'.format((address >> 11) & 0x1f, (address >> 8) & 0x7, address & 0xff)

    @staticmethod
    def pack_knx_group_address(address):
        """Pack KNX group address.

        pack_knx_group_address('6/0/57')
        12345
        """
        assert isinstance(address, str), 'Address should be a string'
        parts = address.split('/')
        return (int(parts[0]) << 11) + (int(parts[1]) << 8) + (int(parts[2]))

    @staticmethod
    def parse_knx_device_serial(address):
        """Parse a KNX device serial to human readable format.

        parse_knx_device_serial(b'\x00\x00\x00\x00\X12\x23')
        '000000005C58'
        """
        assert isinstance(address, bytes), 'Address should be bytes'
        return '{0:02X}{1:02X}{2:02X}{3:02X}{4:02X}{5:02X}'.format(*address)

    @staticmethod
    def parse_mac_address(address):
        """Parse a MAC address to human readable format.

        parse_mac_address(b'\x12\x34\x56\x78\x90\x12')
        '12:34:56:78:90:12'
        """
        assert isinstance(address, bytes), 'Address should be bytes'
        return '{0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}'.format(*address)

    @staticmethod
    def parse_device_descriptor(desc):
        """Parse device descriptors to three separate integers.

        parse_device_descriptor(1793)
        (0, 112, 1)
        """
        assert isinstance(desc, int), 'Device descriptor is not an integer'
        desc = format(desc, '04x')
        medium = int(desc[0])
        dev_type = int(desc[1:-1], 16)
        version = int(desc[-1])
        return medium, dev_type, version

    def set_peer(self, peer):
        assert isinstance(peer, tuple), 'Peer is not a tuple'
        self.source, self.port = peer

    def set_source_ip(self, address):
        self.source = address

    def set_source_port(self, port):
        assert isinstance(port, int), 'Port is not an int'
        self.port = port

    def set_knx_source(self, address):
        """Set the KNX source address of a KnxMessage instance."""
        self.knx_source = self.pack_knx_address(address)

    def set_knx_destination(self, address):
        """Set the KNX destination address of a KnxMessage instance."""
        if '.' in address:
            self.knx_destination = self.pack_knx_address(address)
        elif '/' in address:
            self.knx_destination = self.pack_knx_group_address(address)
        else:
            LOGGER.error('Invalid address %s' % address)

    def get_message(self):
        """Return the current message."""
        # TODO: Maybe use this as string representation?
        return self.message if self.message else None

    def pack_knx_message(self):
        if not self.body:
            message_body = self._pack_knx_body()
        else:
            message_body = self.body
        self.header['total_length'] = 6 + len(message_body)  # header size is always 6
        self.message = self._pack_knx_header()
        self.message.extend(message_body)

    def unpack_knx_message(self, message):
        message = self._unpack_knx_header(message)
        self._unpack_knx_body(message)

    def _pack_knx_header(self):
        try:
            return bytearray(struct.pack('!BBHH',
                               self.header.get('header_length'),
                               self.header.get('protocol_version'),
                               self.header.get('service_type'),
                               self.header.get('total_length')))
        except struct.error as e:
            LOGGER.exception(e)

    def _unpack_knx_header(self, message):
        """Set self.header dict and return message body"""
        try:
            self.header['header_length'], \
            self.header['protocol_version'], \
            self.header['service_type'], \
            self.header['total_length'] = struct.unpack('!BBHH', message[:6])
            return message[6:]
        except struct.error as e:
            LOGGER.exception(e)

    def _pack_knx_body(self, *args, **kwargs):
        """Subclasses must define this method."""
        raise NotImplementedError

    def _unpack_knx_body(self, message):
        """Subclasses must define this method."""
        raise NotImplementedError

    @staticmethod
    def _unpack_stream(fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            LOGGER.exception(e)

    def _parse_knx_body_hpai(self, message):
        try:
            self.body['hpai'] = {}
            self.body['hpai']['structure_length'], \
            self.body['hpai']['protocol_code'], \
            self.body['hpai']['ip_address'], \
            self.body['hpai']['port'] = struct.unpack('!BBHH', message[:8])
            self.body['hpai']['ip_address'] = socket.inet_aton(self.body['hpai']['ip_address'])
            return message[8:]
        except struct.error as e:
            LOGGER.exception(e)

    def _pack_hpai(self):
        hpai = bytearray(struct.pack('!B', 8))  # structure_length
        hpai.extend(struct.pack('!B', 0x01))  # protocol code
        hpai.extend(socket.inet_aton(self.source))
        hpai.extend(struct.pack('!H', self.port))
        return hpai

    def _unpack_hpai(self, message):
        hpai = {}
        hpai['structure_length'] = self._unpack_stream('!B', message)
        hpai['protocol_code'] = self._unpack_stream('!B', message)
        hpai['ip_address'] = socket.inet_ntoa(message.read(4))
        hpai['port'] = self._unpack_stream('!H', message)
        return hpai

    def _unpack_dib_dev_info(self, message):
        dib_dev_info = {}
        dib_dev_info['structure_length'] = self._unpack_stream('!B', message)
        dib_dev_info['description_type'] = self._unpack_stream('!B', message)
        dib_dev_info['knx_medium'] = self._unpack_stream('!B', message)
        dib_dev_info['device_status'] = CemiFrame.unpack_cemi_runstate(self._unpack_stream('!B', message))
        dib_dev_info['knx_address'] = self.parse_knx_address(self._unpack_stream('!H', message))
        dib_dev_info['project_install_identifier'] = self._unpack_stream('!H', message)
        dib_dev_info['knx_device_serial'] = self.parse_knx_device_serial(
            self._unpack_stream('!6s', message))
        dib_dev_info['knx_dev_multicast_address'] = socket.inet_ntoa(message.read(4))
        dib_dev_info['knx_mac_address'] = self.parse_mac_address(self._unpack_stream('!6s', message))
        dib_dev_info['device_friendly_name'] = self._unpack_stream('!30s', message)
        return dib_dev_info

    def _unpack_dib_supp_sv_families(self, message):
        dib_supp_sv_families = collections.OrderedDict()
        dib_supp_sv_families['structure_length'] = self._unpack_stream('!B', message)
        dib_supp_sv_families['description_type'] = self._unpack_stream('!B', message)
        dib_supp_sv_families['families'] = {}
        for i in range(int((dib_supp_sv_families['structure_length'] - 2) / 2)):
            service_id = self._unpack_stream('!B', message)
            version = self._unpack_stream('!B', message)
            dib_supp_sv_families['families'][service_id] = {}
            dib_supp_sv_families['families'][service_id]['version'] = version
        return dib_supp_sv_families
