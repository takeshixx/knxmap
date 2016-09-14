"""KNXnet/IP message implementations required bny KNXmap."""
import collections
import io
import logging
import socket
import struct

from libknxmap.data.constants import *

__all__ = ['parse_message',
           'KnxMessage',
           'KnxSearchRequest',
           'KnxSearchResponse',
           'KnxDescriptionRequest',
           'KnxDescriptionResponse',
           'KnxConnectRequest',
           'KnxConnectResponse',
           'KnxTunnellingRequest',
           'KnxTunnellingAck',
           'KnxConnectionStateRequest',
           'KnxConnectionStateResponse',
           'KnxDisconnectRequest',
           'KnxDisconnectResponse',
           'KnxDeviceConfigurationRequest',
           'KnxDeviceConfigurationAck',
           'KnxRoutingIndication',
           'KnxRoutingLostMessage',
           'KnxRoutingBusy']

LOGGER = logging.getLogger(__name__)


def parse_message(data):
    """
    Determines the message type of data and returns a corresponding class instance. This is a helper
    function for data that has been received from a KNXnet/IP gateway.

    :param data: Incoming data from a KNXnet/IP gateway.
    :return: A class instance of any KnxMessage subclass or None if data is not a valid KNX message.
    """
    try:
        _, _, message_type = struct.unpack('>BBH', data[:4])
        message_type = int(message_type)
    except struct.error as e:
        LOGGER.exception(e)
        return
    except ValueError as e:
        LOGGER.exception(e)
        return

    if message_type == KNX_MESSAGE_TYPES.get('SEARCH_RESPONSE'):
        LOGGER.debug('Parsing KnxSearchResponse')
        return KnxSearchResponse(data)
    elif message_type == KNX_MESSAGE_TYPES.get('DESCRIPTION_RESPONSE'):
        LOGGER.debug('Parsing KnxDescriptionResponse')
        return KnxDescriptionResponse(data)
    elif message_type == KNX_MESSAGE_TYPES.get('CONNECT_RESPONSE'):
        LOGGER.debug('Parsing KnxConnectResponse')
        return KnxConnectResponse(data)
    elif message_type == KNX_MESSAGE_TYPES.get('TUNNELLING_REQUEST'):
        LOGGER.debug('Parsing KnxTunnellingRequest')
        return KnxTunnellingRequest(data)
    elif message_type == KNX_MESSAGE_TYPES.get('TUNNELLING_ACK'):
        LOGGER.debug('Parsing KnxTunnelingAck')
        return KnxTunnellingAck(data)
    elif message_type == KNX_MESSAGE_TYPES.get('CONNECTIONSTATE_REQUEST'):
        LOGGER.debug('Parsing KnxConnectionStateRequest')
        return KnxConnectionStateRequest(data)
    elif message_type == KNX_MESSAGE_TYPES.get('CONNECTIONSTATE_RESPONSE'):
        LOGGER.debug('Parsing KnxConnectionStateResponse')
        return KnxConnectionStateResponse(data)
    elif message_type == KNX_MESSAGE_TYPES.get('DISCONNECT_REQUEST'):
        LOGGER.debug('Parsing KnxDisconnectRequest')
        return KnxDisconnectRequest(data)
    elif message_type == KNX_MESSAGE_TYPES.get('DISCONNECT_RESPONSE'):
        LOGGER.debug('Parsing KnxDisconnectResponse')
        return KnxDisconnectResponse(data)
    elif message_type == KNX_MESSAGE_TYPES.get('DEVICE_CONFIGURATION_REQUEST'):
        LOGGER.debug('Parsing KnxDeviceConfigurationRequest')
        return KnxDeviceConfigurationRequest(data)
    elif message_type == KNX_MESSAGE_TYPES.get('DEVICE_CONFIGURATION_RESPONSE'):
        LOGGER.debug('Parsing KnxDeviceConfigurationAck')
        return KnxDeviceConfigurationAck(data)
    else:
        LOGGER.error('Unknown message type: {}'.format(message_type))
        return None


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
        self.cemi_message_code = None

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
        assert isinstance(address, int)
        return '{}.{}.{}'.format((address >> 12) & 0xf, (address >> 8) & 0xf, address & 0xff)

    @staticmethod
    def pack_knx_address(address):
        """Pack physical/individual KNX address.

        pack_knx_address('15.15.255')
        65535
        """
        assert isinstance(address, str)
        parts = address.split('.')
        return (int(parts[0]) << 12) + (int(parts[1]) << 8) + (int(parts[2]))

    @staticmethod
    def parse_knx_group_address(address):
        """Parse KNX group address.

        parse_knx_group_address(12345)
        '6/0/57'
        """
        assert isinstance(address, int)
        return '{}/{}/{}'.format((address >> 11) & 0x1f, (address >> 8) & 0x7, address & 0xff)

    @staticmethod
    def pack_knx_group_address(address):
        """Pack KNX group address.

        pack_knx_group_address('6/0/57')
        12345
        """
        assert isinstance(address, str)
        parts = address.split('/')
        return (int(parts[0]) << 11) + (int(parts[1]) << 8) + (int(parts[2]))

    @staticmethod
    def parse_knx_device_serial(address):
        """Parse a KNX device serial to human readable format.

        parse_knx_device_serial(b'\x00\x00\x00\x00\X12\x23')
        '000000005C58'
        """
        assert isinstance(address, bytes)
        return '{0:02X}{1:02X}{2:02X}{3:02X}{4:02X}{5:02X}'.format(*address)

    @staticmethod
    def parse_mac_address(address):
        """Parse a MAC address to human readable format.

        parse_mac_address(b'\x12\x34\x56\x78\x90\x12')
        '12:34:56:78:90:12'
        """
        assert isinstance(address, bytes)
        return '{0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}'.format(*address)

    @staticmethod
    def parse_device_descriptor(desc):
        """Parse device descriptors to three separate integers.

        parse_device_descriptor(1793)
        (0, 112, 1)
        """
        assert isinstance(desc, int), 'Device descriptor is not an int'
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
            LOGGER.error('Invalid address')

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
        self.message += message_body

    def unpack_knx_message(self, message):
        message = self._unpack_knx_header(message)
        self._unpack_knx_body(message)

    def _pack_knx_header(self):
        try:
            return struct.pack('!BBHH',
                               self.header.get('header_length'),
                               self.header.get('protocol_version'),
                               self.header.get('service_type'),
                               self.header.get('total_length'))
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
            self.body['hpai'] = dict()
            self.body['hpai']['structure_length'], \
            self.body['hpai']['protocol_code'], \
            self.body['hpai']['ip_address'], \
            self.body['hpai']['port'] = struct.unpack('!BBHH', message[:8])
            self.body['hpai']['ip_address'] = socket.inet_aton(self.body['hpai']['ip_address'])
            return message[8:]
        except struct.error as e:
            LOGGER.exception(e)

    def _pack_hpai(self):
        hpai = struct.pack('!B', 8)  # structure_length
        hpai += struct.pack('!B', 0x01)  # protocol code
        hpai += socket.inet_aton(self.source)
        hpai += struct.pack('!H', self.port)
        return hpai

    def _unpack_hpai(self, message):
        hpai = dict()
        hpai['structure_length'] = self._unpack_stream('!B', message)
        hpai['protocol_code'] = self._unpack_stream('!B', message)
        hpai['ip_address'] = socket.inet_ntoa(message.read(4))
        hpai['port'] = self._unpack_stream('!H', message)
        return hpai

    def _unpack_dib_dev_info(self, message):
        dib_dev_info = dict()
        dib_dev_info['structure_length'] = self._unpack_stream('!B', message)
        dib_dev_info['description_type'] = self._unpack_stream('!B', message)
        dib_dev_info['knx_medium'] = self._unpack_stream('!B', message)
        dib_dev_info['device_status'] = self.unpack_cemi_runstate(self._unpack_stream('!B', message))
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
            dib_supp_sv_families['families'][service_id] = dict()
            dib_supp_sv_families['families'][service_id]['version'] = version
        return dib_supp_sv_families

    @staticmethod
    def pack_cemi_cf1(confirm=False, acknowledge_req=False, priority=0x00,
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
    def unpack_cemi_cf1(data):
        """Parse controlfield1 to a drict."""
        cf = dict()
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
    def pack_cemi_cf2(ext_frame_format=0x00, hop_count=6, address_type=False):
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
        cf |= (1 if address_type else 0) << 7
        return cf

    @staticmethod
    def unpack_cemi_cf2(data):
        """Parse controlfield2 to a drict."""
        cf = dict()
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

    @staticmethod
    def pack_cemi_runstate(prog_mode=False, link_layer_active=False, transport_layer_active=False,
                           app_layer_active=False, serial_interface_active=False, user_app_run=False,
                           bcu_download_mode=False, parity=0):
        """Pack runstate field of the cEMI message.

        Bit  |
        ------+---------------------------------------------------------------
          7   | Parity
              | Even parity for bit 0-6
        ------+---------------------------------------------------------------
          6   | DM
              | BCU in download mode
        ------+---------------------------------------------------------------
          5   | UE
              | User application running
        ------+---------------------------------------------------------------
          4   | SE
              | Serial interface active
        ------+---------------------------------------------------------------
          3   | ALE
              | Application layer active
        ------+---------------------------------------------------------------
          2   | TLE
              | Transport layer active
        ------+---------------------------------------------------------------
          1   | LLM
              | Link layer active
        ------+---------------------------------------------------------------
          0   | PROG
              | Device is in programming mode
        ------+---------------------------------------------------------------"""
        state = 0
        state |= (1 if prog_mode else 0) << 0
        state |= (1 if link_layer_active else 0) << 1
        state |= (1 if transport_layer_active else 0) << 2
        state |= (1 if app_layer_active else 0) << 3
        state |= (1 if serial_interface_active else 0) << 4
        state |= (1 if user_app_run else 0) << 5
        state |= (1 if bcu_download_mode else 0) << 6
        for i in range(7):
            parity ^= (state >> i) & 1
        state |= parity << 7
        return state

    @staticmethod
    def unpack_cemi_runstate(data):
        """Parse runstate field to a drict."""
        state = collections.OrderedDict()
        state['PROG_MODE'] = (data >> 0) & 1
        state['LINK_LAYER'] = (data >> 1) & 1
        state['TRANSPORT_LAYER'] = (data >> 2) & 1
        state['APP_LAYER'] = (data >> 3) & 1
        state['SERIAL_INTERFACE'] = (data >> 4) & 1
        state['USER_APP'] = (data >> 5) & 1
        state['BC_DM'] = (data >> 6) & 1
        # We don't really care about the parity
        # state['parity'] = (data >> 7) & 1
        return state

    def _pack_cemi(self, message_code=None, *args, **kwargs):
        message_code = message_code if message_code else self.cemi_message_code
        cemi = struct.pack('!B', message_code)  # cEMI message code
        # TODO: implement variable length if additional information is included
        cemi += struct.pack('!B', 0)  # add information length
        cemi += struct.pack('!B', self.pack_cemi_cf1())  # controlfield 1
        cemi += struct.pack('!B', self.pack_cemi_cf2(*args, **kwargs))  # controlfield 2
        cemi += struct.pack('!H', self.knx_source)  # source address (KNX address)
        cemi += struct.pack('!H', self.knx_destination)  # KNX destination address (either group or physical)
        return cemi

    def _unpack_cemi(self, message):
        cemi = dict()
        cemi['message_code'] = self._unpack_stream('!B', message)
        cemi['information_length'] = self._unpack_stream('!B', message)

        if cemi['information_length'] is not 0:
            cemi['additional_information'] = {}
            cemi['additional_information']['busmonitor_info'] = self._unpack_stream('!B', message)
            cemi['additional_information']['busmonitor_info_length'] = self._unpack_stream('!B', message)
            cemi['additional_information']['busmonitor_info_error_flags'] = self._unpack_stream('!B', message)
            cemi['additional_information']['extended_relative_timestamp'] = self._unpack_stream('!B', message)
            cemi['additional_information']['extended_relative_timestamp'] = self._unpack_stream('!B', message)
            cemi['additional_information']['extended_relative_timestamp'] = self._unpack_stream('!I', message)
            cemi['raw_frame'] = message.read()
            return cemi

        cemi['controlfield_1'] = self.unpack_cemi_cf1(self._unpack_stream('!B', message))
        cemi['controlfield_2'] = self.unpack_cemi_cf2(self._unpack_stream('!B', message))
        cemi['knx_source'] = self._unpack_stream('!H', message)
        cemi['knx_destination'] = self._unpack_stream('!H', message)
        cemi['npdu_len'] = self._unpack_stream('!B', message)

        tpci_unpacked = dict()
        tpci = self._unpack_stream('!{}s'.format(cemi['npdu_len'] + 1), message)

        tpci_unpacked['tpci_type'] = 0
        tpci_unpacked['tpci_type'] |= ((tpci[0] >> 6) & 1) << 0
        tpci_unpacked['tpci_type'] |= ((tpci[0] >> 7) & 1) << 1
        tpci_unpacked['sequence'] = 0
        tpci_unpacked['sequence'] |= ((tpci[0] >> 2) & 1) << 0
        tpci_unpacked['sequence'] |= ((tpci[0] >> 3) & 1) << 1
        tpci_unpacked['sequence'] |= ((tpci[0] >> 4) & 1) << 2
        tpci_unpacked['sequence'] |= ((tpci[0] >> 5) & 1) << 3

        cemi['tpci'] = dict()
        cemi['tpci']['type'] = tpci_unpacked['tpci_type']
        cemi['tpci']['sequence'] = tpci_unpacked['sequence']

        if tpci_unpacked['tpci_type'] is [2, 3]:
            # Control data includes a status field
            tpci_unpacked['status'] = 0
            tpci_unpacked['status'] |= ((tpci[0] >> 0) & 1) << 0
            tpci_unpacked['status'] |= ((tpci[0] >> 1) & 1) << 1
            cemi['tpci']['status'] = tpci_unpacked['status']

        if cemi['npdu_len'] > 0:
            tpci_unpacked['apci'] = 0
            tpci_unpacked['apci'] |= ((tpci[1] >> 6) & 1) << 0
            tpci_unpacked['apci'] |= ((tpci[1] >> 7) & 1) << 1
            tpci_unpacked['apci'] |= ((tpci[0] >> 0) & 1) << 2
            tpci_unpacked['apci'] |= ((tpci[0] >> 1) & 1) << 3

            if tpci_unpacked['apci'] in CEMI_APCI_TYPES.values():
                tpci_unpacked['apci_data'] = 0
                tpci_unpacked['apci_data'] |= ((tpci[1] >> 0) & 1) << 0
                tpci_unpacked['apci_data'] |= ((tpci[1] >> 1) & 1) << 1
                tpci_unpacked['apci_data'] |= ((tpci[1] >> 2) & 1) << 2
                tpci_unpacked['apci_data'] |= ((tpci[1] >> 3) & 1) << 3
                tpci_unpacked['apci_data'] |= ((tpci[1] >> 4) & 1) << 4
                tpci_unpacked['apci_data'] |= ((tpci[1] >> 5) & 1) << 5
            else:
                tpci_unpacked['apci'] <<= 2
                tpci_unpacked['apci'] |= ((tpci[1] >> 4) & 1) << 0
                tpci_unpacked['apci'] |= ((tpci[1] >> 5) & 1) << 1

                if tpci_unpacked['apci'] in CEMI_APCI_TYPES.values():
                    tpci_unpacked['apci_data'] = 0
                    tpci_unpacked['apci_data'] |= ((tpci[1] >> 0) & 1) << 0
                    tpci_unpacked['apci_data'] |= ((tpci[1] >> 1) & 1) << 1
                    tpci_unpacked['apci_data'] |= ((tpci[1] >> 2) & 1) << 2
                    tpci_unpacked['apci_data'] |= ((tpci[1] >> 3) & 1) << 3
                else:
                    tpci_unpacked['apci'] <<= 4
                    tpci_unpacked['apci'] |= ((tpci[1] >> 0) & 1) << 0
                    tpci_unpacked['apci'] |= ((tpci[1] >> 1) & 1) << 1
                    tpci_unpacked['apci'] |= ((tpci[1] >> 2) & 1) << 2
                    tpci_unpacked['apci'] |= ((tpci[1] >> 3) & 1) << 3

            cemi['apci'] = dict()
            cemi['apci']['type'] = tpci_unpacked['apci']
            cemi['apci']['data'] = tpci_unpacked.get('apci_data')
            cemi['data'] = tpci[2:]

        # TODO: if there is more data, read it now
        # TODO: read cemi['npdu_len']-1 bytes
        return cemi

    def tpci_unnumbered_control_data(self, ucd_type):
        assert ucd_type in TPCI_UNNUMBERED_CONTROL_DATA_TYPES.keys(), 'Invalid UCD type: {}'.format(ucd_type)
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 0)  # Data length
        npdu = CEMI_TPCI_TYPES.get('UCD') << 14
        npdu |= TPCI_UNNUMBERED_CONTROL_DATA_TYPES.get(ucd_type) << 8
        cemi += struct.pack('!H', npdu)
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def tpci_numbered_control_data(self, ncd_type, sequence=0):
        assert ncd_type in TPCI_NUMBERED_CONTROL_DATA_TYPES.keys(), 'Invalid NCD type: {}'.format(ncd_type)
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 0)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NCD') << 14
        npdu |= sequence << 10
        npdu |= TPCI_NUMBERED_CONTROL_DATA_TYPES.get(ncd_type) << 8
        cemi += struct.pack('!H', npdu)
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_device_descriptor_read(self, sequence=0):
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 1)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_DeviceDescriptor_Read'] << 0
        cemi += struct.pack('!H', npdu)
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_individual_address_read(self, sequence=0):
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 1)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_IndividualAddress_Read'] << 0
        cemi += struct.pack('!H', npdu)
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_authorize_request(self, sequence=0, key=0xffffffff):
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 6)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_Authorize_Request'] << 0
        cemi += struct.pack('!H', npdu)
        cemi += struct.pack('!B', 0)  # reserved
        cemi += struct.pack('!I', key)  # key
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_property_value_read(self, sequence=0, object_index=0, property_id=0x0f,
                                 num_elements=1, start_index=1):
        """A_PropertyValue_Read"""
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 5)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_PropertyValue_Read'] << 0
        cemi += struct.pack('!H', npdu)
        cemi += struct.pack('!B', object_index)  # object index
        cemi += struct.pack('!B', property_id)  # property id
        count_index = num_elements << 12
        count_index |= start_index << 0
        cemi += struct.pack('!H', count_index)  # number of elements + start index
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_property_description_read(self, sequence=0, object_index=0, property_id=0x0f,
                                       num_elements=1, start_index=1):
        """A_PropertyDescription_Read"""
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 5)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_PropertyDescription_Read'] << 0
        cemi += struct.pack('!H', npdu)
        cemi += struct.pack('!B', object_index)  # object index
        cemi += struct.pack('!B', property_id)  # property id
        count_index = num_elements << 12
        count_index |= start_index << 0
        cemi += struct.pack('!H', count_index)  # number of elements + start index
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_user_manufacturer_info_read(self, sequence=0):
        """A_UserManufacturerInfo_Read"""
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 1)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_UserManufacturerInfo_Read'] << 0
        cemi += struct.pack('!H', npdu)
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_adc_read(self, sequence=0):
        """A_ADC_Read"""
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 2)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_ADC_Read'] << 0
        npdu |= 1 << 0  # channel nr
        cemi += struct.pack('!H', npdu)
        cemi += struct.pack('!B', 0x08)  # data
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_memory_read(self, sequence=0, memory_address=0x0060, read_count=1):
        """A_Memory_Read

        0x0060 -> run state
        0x010d -> run error

        EEPROM:
        0x0100 OptionReg: Option Register (MC68HC05B06)
        0x0101 ManData: Data provided by the manufacturer of the BCU (see further down) (3 Bytes)
        0x0104 Manufact: ID of the application manufacturer
        0x0105 DevTyp: Manufacturer-specific device type ID (2 Bytes)
        0x0107 Version: Version number of the application program
        0x0108 CheckLim: Specifies the end address of the EEPROM range that is to be covered by
                         the system check procedure. The address area to be checked ranges from
                         $0108 to $100+ChekLim-1.
        0x0109 PEI type: Type of PEI required for the application program
        0x010A SyncRate: Baud rate for the PEIs of type 12,14 ‘serial synchronous PEI’
        0x010B PortCDDR: Defines the directions of data flow of port C for a PEI of type 17 ‘
                         programmable I/O’
        0x010C PortADDR: Defines the directions of data flow for port A.
        0x010D RunError: Runtime error flags
                          Bit  |
                         ------+---------------------------------------------------------------
                           7   | Unknown
                               |
                         ------+---------------------------------------------------------------
                           6   | SYS3_ERR (internal system failure)
                               | Memory control block broken
                         ------+---------------------------------------------------------------
                           5   | SYS2_ERR (internal system failure)
                               | Temperature
                         ------+---------------------------------------------------------------
                           4   | OBJ_ERR
                               | RAM flag failure
                         ------+---------------------------------------------------------------
                           3   | STK_OVL
                               | Stack overload
                         ------+---------------------------------------------------------------
                           2   | EEPROM_ERR
                               | EEPROM encountered checksum error
                         ------+---------------------------------------------------------------
                           1   | SYS1_ERR (internal system failure)
                               | Wrong parity bit
                         ------+---------------------------------------------------------------
                           0   | SYS0_ERR (internal system failure)
                               | Message buffer offset broken
                         ------+---------------------------------------------------------------
        0x010E RouteCnt: Routing counter constant (layer 3), structure:
                         0ccc0000, ccc = routing counter constant (0 to 7)
        0x010F MxRstCnt: Contains the INAK and BUSY retries (layer 2), structure:
                         bbb00iii, bbb=BUSY retries
                         iii=INAK retries
        0x0110 ConfigDes: Configuration descriptor (see further down)
        0x0111 AssocTabPtr: Pointer to the Association Table (layer 7)
        0x0112 CommsTabPtr: Pointer to the Table of group objects
        0x0113 UsrInitPtr: Pointer to the initialization routine of the application program
        0x0114 UsrPrgPtr: Pointer to the application program
        0x0115 UsrSavPtr: Pointer to the SAVE subroutine of the application program
        0x0116 AdrTab: Address table (layers 2 and 4)
                       m = No. of group addresses (1 + (1 + m) * 2 Bytes)
        ...0x01FE       Application program UsrPrg,
                        Initialisation program UsrInit,
                        SAVE subroutine UsrSav
        0x01FF EE_EXOR: EEPROM checksum for the range to be checked (cp. CheckLim)
        """
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 3)  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_Memory_Read'] << 4
        npdu |= read_count << 0  # number of octets to read/write
        cemi += struct.pack('!H', npdu)
        cemi += struct.pack('!H', memory_address)  # memory address
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_memory_write(self, sequence=0, memory_address=0x0060, write_count=1,
                          data=b'\x00'):
        """A_Memory_Write"""
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'))
        cemi += struct.pack('!B', 3 + len(data))  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_Memory_Write'] << 4
        npdu |= write_count << 0  # number of octets to read/write
        cemi += struct.pack('!H', npdu)
        cemi += struct.pack('!H', memory_address)  # memory address
        cemi += struct.pack('!{}s'.format(len(data)), data)
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()

    def apci_group_value_write(self, value=0):
        cemi = self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req'), address_type=True)
        cemi += struct.pack('!B', 1)  # Data length
        npdu = CEMI_TPCI_TYPES.get('UDP') << 14
        npdu |= CEMI_APCI_TYPES['A_GroupValue_Write'] << 6
        npdu |= value << 0
        cemi += struct.pack('!H', npdu)
        self._pack_knx_body(cemi=cemi)
        self.pack_knx_message()


class KnxSearchRequest(KnxMessage):
    def __init__(self, message=None, sockname=None):
        super(KnxSearchRequest, self).__init__()
        if message:
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
        self.body += self._pack_hpai()
        # Connection request information
        if self.connection_type == 0x04:
            self.body += struct.pack('!B', 4)  # structure_length
        else:
            self.body += struct.pack('!B', 2)  # structure_length
        # TODO: implement other connections (routing, object server)
        self.body += struct.pack('!B', self.connection_type)  # connection type
        if self.connection_type == 0x04:
            self.body += struct.pack('!B', self.layer_type)  # knx layer type
            self.body += struct.pack('!B', 0x00)  # reserved
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            # Discovery endpoint
            self.body = self._unpack_hpai(message)
            # Data endpoint
            self.body['data_endpoint'] = self._unpack_hpai(message)
            # Connection request information
            self.body['connection_request_information'] = dict()
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
            self.body['data_block'] = dict()
            self.body['data_block']['structure_length'] = self._unpack_stream('!B', message)
            self.body['data_block']['connection_type'] = self._unpack_stream('!B', message)
            if self.body['data_block']['connection_type'] == 0x04:
                self.body['data_block']['knx_address'] = super().parse_knx_address(self._unpack_stream('!H', message))
        except Exception as e:
            LOGGER.exception(e)


class KnxTunnellingRequest(KnxMessage):
    def __init__(self, message=None, sockname=None, communication_channel=None,
                 knx_source=None, knx_destination=None, sequence_count=0, message_code=0x11,
                 cemi_ndpu_len=0):
        super(KnxTunnellingRequest, self).__init__()
        if message:
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('TUNNELLING_REQUEST')
            self.communication_channel = communication_channel
            self.sequence_count = sequence_count
            self.cemi_message_code = message_code
            self.cemi_npdu_len = cemi_ndpu_len
            if knx_source:
                self.set_knx_source(knx_source)
            if knx_destination:
                self.set_knx_destination(knx_destination)

            try:
                self.source, self.port = sockname
                self.pack_knx_message()
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self, cemi=None):
        self.body = struct.pack('!B', 4)  # structure_length
        self.body += struct.pack('!B', self.communication_channel)  # channel id
        self.body += struct.pack('!B', self.sequence_count)  # sequence counter
        self.body += struct.pack('!B', 0)  # reserved
        # cEMI
        if cemi:
            self.body += cemi
        else:
            self.body += self._pack_cemi()
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['sequence_counter'] = self._unpack_stream('!B', message)
            self.body['reserved'] = self._unpack_stream('!B', message)
            # cEMI
            self.body['cemi'] = self._unpack_cemi(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxTunnellingAck(KnxMessage):
    def __init__(self, message=None, communication_channel=None, sequence_count=0):
        super(KnxTunnellingAck, self).__init__()
        if message:
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('TUNNELLING_ACK')
            self.communication_channel = communication_channel
            self.sequence_count = sequence_count
            self.pack_knx_message()

    def _pack_knx_body(self):
        self.body = struct.pack('!B', 4)  # structure_length
        self.body += struct.pack('!B', self.communication_channel)  # channel id
        self.body += struct.pack('!B', self.sequence_count)  # sequence counter
        self.body += struct.pack('!B', 0)  # status
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


class KnxConnectionStateRequest(KnxMessage):
    def __init__(self, message=None, sockname=None, communication_channel=None):
        super(KnxConnectionStateRequest, self).__init__()
        if message:
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
        self.body = struct.pack('!B', self.communication_channel)  # channel id
        self.body += struct.pack('!B', 0)  # reserved
        # HPAI
        self.body += self._pack_hpai()
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
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('CONNECTIONSTATE_RESPONSE')
            self.communication_channel = communication_channel
            self.pack_knx_message()

    def _pack_knx_body(self):
        # discovery endpoint
        self.body = struct.pack('!B', self.communication_channel)  # channel id
        self.body += struct.pack('!B', 0)  # status
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
        self.body = struct.pack('!B', self.communication_channel)  # channel id
        self.body += struct.pack('!B', 0)  # reserved
        # HPAI
        self.body += self._pack_hpai()
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
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('DISCONNECT_RESPONSE')
            self.communication_channel = communication_channel
            self.pack_knx_message()

    def _pack_knx_body(self):
        # discovery endpoint
        self.body = struct.pack('!B', self.communication_channel)  # channel id
        self.body += struct.pack('!B', 0)  # status
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)
        except Exception as e:
            LOGGER.exception(e)


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
        self.body = struct.pack('!B', 4)  # structure_length
        self.body += struct.pack('!B', self.communication_channel)  # channel id
        self.body += struct.pack('!B', self.sequence_count)  # sequence counter
        self.body += struct.pack('!B', 0)  # reserved
        # cEMI
        # if cemi:
        #    self.body += cemi
        # else:
        #    self.body += self._pack_cemi()

        self.body += struct.pack('!B', self.cemi_message_code)  # M_PropRead.req
        # self.body += struct.pack('!B', CEMI_MESSAGE_CODES.get('L_Data.req'))
        self.body += struct.pack('!H', 11)
        self.body += struct.pack('!B', 11)
        self.body += struct.pack('!B', PARAMETER_OBJECTS.get('PID_ADDITIONAL_INDIVIDUAL_ADDRESSES'))
        # self.body += struct.pack('!B', DEVICE_OBJECTS.get('PID_SERIAL_NUMBER'))
        # self.body += struct.pack('!H', 0x1001)
        self.body += struct.pack('!B', 0x10)
        self.body += struct.pack('!B', 0x00)

        print("body")
        print(self.body)

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
        self.body = struct.pack('!B', 4)  # structure_length
        self.body += struct.pack('!B', self.communication_channel)  # channel id
        self.body += struct.pack('!B', self.sequence_count)  # sequence counter
        self.body += struct.pack('!B', 0)  # status
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
        self.body = b''
        if cemi:
            self.body += cemi
        else:
            self.body += self._pack_cemi()
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
        self.body = struct.pack('!B', 4)  # structure_length
        self.body += struct.pack('!B', 0)  # device state
        self.body += struct.pack('!H', 0)  # number of lost messages
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
        self.body = struct.pack('!B', 4)  # structure_length
        self.body += struct.pack('!B', 0)  # device state
        self.body += struct.pack('!H', 0)  # routing busy wait time
        self.body += struct.pack('!H', 0)  # routing busy control field
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
