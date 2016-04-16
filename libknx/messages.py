"""KNXnet/IP message implementations required bny knxmap."""
import struct
import socket
import io
import collections
import logging

import libknx.utils

__all__ = ['KNX_CONSTANTS',
           'KNX_SERVICES',
           'KNX_MESSAGE_TYPES',
           'KNX_STATUS_CODES',
           'KnxSearchRequest',
           'KnxSearchResponse',
           'KnxDescriptionRequest',
           'KnxDescriptionResponse',
           'KnxConnectRequest',
           'KnxConnectResponse',
           'KnxTunnellingRequest',
           'KnxTunnellingAck',
           'KnxDisconnectRequest',
           'KnxDisconnectResponse']

LOGGER = logging.getLogger(__name__)

KNX_CONSTANTS = {
    'KNXNETIP_VERSION_10': 0x10,
    'HEADER_SIZE_10': 0x06}

KNX_SERVICES = {
    0x02: 'KNXnet/IP Core',
    0x03: 'KNXnet/IP Device Management',
    0x04: 'KNXnet/IP Tunnelling',
    0x05: 'KNXnet/IP Routing',
    0x06: 'KNXnet/IP Remote Logging',
    0x08: 'KNXnet/IP Object Server',
    0x07: 'KNXnet/IP Remote Configuration and Diagnosis'}

KNX_MESSAGE_TYPES = {
    # KNXnet/IP-Core-Services
    0x0201: 'SEARCH_REQUEST',
    0x0202: 'SEARCH_RESPONSE',
    0x0203: 'DESCRIPTION_REQUEST',
    0x0204: 'DESCRIPTION_RESPONSE',
    0x0205: 'CONNECT_REQUEST',
    0x0206: 'CONNECT_RESPONSE',
    0x0207: 'CONNECTIONSTATE_REQUEST',
    0x0208: 'CONNECTIONSTATE_RESPONSE',
    0x0209: 'DISCONNECT_REQUEST',
    0x020a: 'DISCONNECT_RESPONSE',
    # Device-Management-Services
    0x0310: 'DEVICE_CONFIGURATION_REQUEST',
    0x0311: 'DEVICE_CONFIGURATION_REQUEST',
    # Tunnelling-Services
    0x0420: 'TUNNELLING_REQUEST',
    0x0421: 'TUNNELLING_ACK',
    # Routing-Services
    0x0530: 'ROUTING_INDICATION',
    0x0531: 'ROUTING_LOST_MESSAGE',
    0x0532: 'ROUTING_BUSY',
    # Remoting-and-Configuration
    0x0740: 'REMOTE_DIAGNOSTIC_REQUEST',
    0x0741: 'REMOTE_DIAGNOSTIC_RESPONSE',
    0x0742: 'REMOTE_BASIC_CONFIGURATION_REQUEST',
    0x0743: 'REMOTE_RESET_REQUEST'}

KNX_STATUS_CODES = {
    0x00: 'E_NO_ERROR',
    0x01: 'E_HOST_PROTOCOL_TYPE',
    0x02: 'E_VERSION_NOT_SUPPORTED',
    0x04: 'E_SEQUENCE_NUMBER',
    # CONNECT_RESPONSE status codes
    0x22: 'E_CONNECTION_TYPE', # requested connection type not supported
    0x23: 'E_CONNECTION_OPTION', # one or more connection options not supported
    0x24: 'E_NO_MORE_CONNECTIONS', # max amount of connections reached,
    # CONNECTIONSTATE_RESPONSE status codes
    0x21: 'E_CONNECTION_ID',
    0x26: 'E_DATA_CONNECTION',
    0x27: 'E_KNX_CONNECTION',
    # CONNECT_ACK status codes
    0x29: 'E_TUNNELLING_LAYER'}


class KnxMessage(object):
    header = {
        'header_length': KNX_CONSTANTS['HEADER_SIZE_10'],
        'protocol_version': KNX_CONSTANTS['KNXNETIP_VERSION_10'],
        'service_type': None,
        'total_length': None}
    body = {}
    message = None

    def set_source_ip(self, address):
        #if libknx.utils.is_valid_knx_bus_address(address):
        self.source = address

    def set_destination_ip(self, address):
        #if libknx.utils.is_valid_knx_bus_address(address):
        self.destination = socket.inet_aton(address)

    def set_source_port(self, port):
        self.port = port

    def set_knx_source(self, address):
        self.knx_source = libknx.utils.knx_address_aton(address)

    def set_knx_destination(self, address):
        self.knx_destination = self.pack_knx_address(address)

    def get_message(self):
        return self.message if self.message else False

    @staticmethod
    def parse_knx_address(address):
        return '{}.{}.{}'.format((address >> 12) & 0xf, (address >> 8) & 0xf, address & 0xff)

    @staticmethod
    def pack_knx_address(address):
        parts = address.split('.')
        return (int(parts[0]) << 12) + (int(parts[1]) << 8) + (int(parts[2]))

    @staticmethod
    def parse_mac_address(address):
        return '{0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}'.format(*address)

    @staticmethod
    def parse_knx_device_serial(address):
        return '{0:02X}{1:02X}{2:02X}{3:02X}{4:02X}{5:02X}'.format(*address)

    def pack_knx_message(self):
        self.message = self._pack_knx_header()
        self.message += self._pack_knx_body()

    def _pack_knx_header(self):
        try:
            return struct.pack('!BBHH',
                               self.header.get('header_length'),
                               self.header.get('protocol_version'),
                               self.header.get('service_type'),
                               self.header.get('total_length'))
        except struct.error as e:
            print(e)

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

    def _pack_knx_body(self):
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
            self.body['hpai']['ip_address'] = socket.inet_aton(self.body['hpai']['ip_address']) # most likely not works
            return message[8:]
        except struct.error as e:
            LOGGER.exception(e)

    def _pack_hpai(self):
        hpai = struct.pack('!B', 8) # structure_length
        hpai += struct.pack('!B', 0x01) # protocol code
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
        dib_dev_info['device_status'] = 'PROGMODE_ON' if self._unpack_stream('!B', message) else 'PROGMODE_OFF'
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

    def _pack_cemi(self):
        cemi = struct.pack('!B', 0x11) # message code
        cemi += struct.pack('!B', 0) # add information length
        cemi += struct.pack('!B', 0xbc) # controlfield 1
        cemi += struct.pack('!B', 0xf0) # controlfield 2
        cemi += struct.pack('!H', self.knx_source) # source address (KNX address)
        cemi += struct.pack('!H', self.knx_destination) # destination address (KNX address)
        cemi += struct.pack('!B', 0x01) # NPDU length
        cemi += struct.pack('!B', 0x00) # TPCI: UDT (?)
        cemi += struct.pack('!B', 0x81) # APCI (?)
        return cemi

    def _unpack_cemi(self, message):
        cemi = dict()
        cemi['message_code'] = self._unpack_stream('!B', message)
        cemi['information_length'] = self._unpack_stream('!B', message)
        cemi['controlfield_1'] = self._unpack_stream('!B', message)
        cemi['controlfield_2'] = self._unpack_stream('!B', message)
        cemi['knx_source'] = self._unpack_stream('!H', message)
        cemi['knx_destination'] = self._unpack_stream('!H', message)
        cemi['npdu'] = self._unpack_stream('!B', message)
        cemi['tcpi'] = self._unpack_stream('!B', message)
        cemi['apci'] = self._unpack_stream('!B', message)
        return cemi


class KnxSearchRequest(KnxMessage):

    def __init__(self, message=None, sockname=None):
        try:
            self.source, self.port = sockname
        except TypeError:
            self.source = None
            self.port = None

        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0201
            self.header['total_length'] = 14

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
        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0202

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
        try:
            self.source, self.port = sockname
        except TypeError:
            self.source = None
            self.port = None

        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0203
            self.header['total_length'] = 14

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
        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0204

    def _pack_knx_body(self):
        raise NotImplementedError

    def _unpack_knx_body(self, message):
        message = io.BytesIO(message)
        try:
            message = io.BytesIO(message)
            self.body['dib_dev_info'] = self._unpack_dib_dev_info(message)
            self.body['dib_supp_sv_families'] = self._unpack_dib_supp_sv_families(message)
        except Exception as e:
            LOGGER.exception(e)


class KnxConnectRequest(KnxMessage):

    def __init__(self, message=None, sockname=None):
        try:
            self.source, self.port = sockname
        except TypeError:
            self.source = None
            self.port = None

        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0205
            self.header['total_length'] = 26

    def _pack_knx_body(self):
        # Discovery endpoint
        self.body = self._pack_hpai()
        # Data endpoint
        self.body += self._pack_hpai()
        # Connection request information
        self.body += struct.pack('!B', 4)  # structure_length
        self.body += struct.pack('!B', 0x04)  # connection type
        self.body += struct.pack('!B', 0x02)  # knx layer, TUNNEL_LINKLAYER
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
    ERROR = None

    def __init__(self, message=None):
        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0206
            self.header['total_length'] = 20

    def _pack_knx_body(self):
        raise NotImplementedError

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)

            if self.body['status'] != 0x00:
                # the device encountered an error!
                # TODO: implement some kind of retries and waiting periods
                self.ERROR = KNX_STATUS_CODES[self.body['status']]
                print('KnxConnectionResponse ERROR: {}'.format(self.ERROR))
                return

            self.body['hpai'] = self._unpack_hpai(message)
            # Connection response data block
            self.body['data_block'] = dict()
            self.body['data_block']['structure_length'] = self._unpack_stream('!B', message)
            self.body['data_block']['connection_type'] = self._unpack_stream('!B', message)
            self.body['data_block']['knx_address'] = self.parse_knx_address(self._unpack_stream('!H', message))
        except Exception as e:
            LOGGER.exception(e)


class KnxTunnellingRequest(KnxMessage):

    def __init__(self, message=None, sockname=None, communication_channel=None,
                 knx_source=None, knx_destination=None, sequence_count=0):
        try:
            self.source, self.port = sockname
        except TypeError:
            self.source = None
            self.port = None

        self.communication_channel = communication_channel
        self.sequence_count = sequence_count

        # TODO: just for testing use fixed source/destination address
        self.knx_source = self.pack_knx_address('0.0.0')

        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0420
            self.header['total_length'] = 21

    def _pack_knx_body(self):
        self.body = struct.pack('!B', 4) # structure_length
        self.body += struct.pack('!B', self.communication_channel) # channel id
        self.body += struct.pack('!B', self.sequence_count) # sequence counter
        self.body += struct.pack('!B', 0) # reserved
        # cEMI
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
        self.communication_channel = communication_channel
        self.sequence_count = sequence_count

        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0421
            self.header['total_length'] = 10

    def _pack_knx_body(self):
        self.body = struct.pack('!B', 4) # structure_length
        self.body += struct.pack('!B', self.communication_channel) # channel id
        self.body += struct.pack('!B', self.sequence_count) # sequence counter
        self.body += struct.pack('!B', 0) # status
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


class KnxDisconnectRequest(KnxMessage):

    def __init__(self, message=None, sockname=None, communication_channel=None,
                 knx_source=None, knx_destination=None):
        try:
            self.source, self.port = sockname
        except TypeError:
            self.source = None
            self.port = None

        self.communication_channel = communication_channel

        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0209
            self.header['total_length'] = 16

    def _pack_knx_body(self):
        self.body = struct.pack('!B', self.communication_channel) # channel id
        self.body += struct.pack('!B', 0) # reserved
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

    def __init__(self, message=None, communication_channel=None,
                 knx_source=None, knx_destination=None):

        self.communication_channel = communication_channel

        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x020a
            self.header['total_length'] = 8

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


# TODO: implement CONNECTIONSTATE_REQUEST aka KNX Heartbeat
# * has to be sent by the client every 60s
# * server has to respond within 10s
# * if client doesn't send one withing 120s, server mus tear down connection
#   -> should we even care?

# TODO: implement routing requests (multicast?)
#       ROUTING_INDICATION
#       ROUTING_LOST_MESSAGE

# TODO: implement device configuration requests
#       DEVICE_CONFIGURATION_REQUEST
#       DEVICE_CONFIGURATION_ACK