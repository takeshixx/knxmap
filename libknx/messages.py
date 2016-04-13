"""KNX message implementations that are necessary for the scanning
tasks."""
import struct
import socket
import io

import libknx.utils

# TODO: reset __all__ when all messages are implemented
#__all__ = ['KnxSearchRequest', 'KnxConnectionRequest']

knx_constants = {
    'KNXNETIP_VERSION_10': 0x10,
    'HEADER_SIZE_10': 0x06}

knx_message_types = {
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

knx_service_families = {
    0x02: 'KNXnet/IP Core',
    0x03: 'KNXnet/IP Device Management',
    0x04: 'KNXnet/IP Tunnelling',
    0x05: 'KNXnet/IP Routing',
    0x06: 'KNXnet/IP Remote Logging',
    0x08: 'KNXnet/IP Object Server',
    0x07: 'KNXnet/IP Remote Configuration and Diagnosis'}

knx_status_codes = {
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
        'header_length': 0x06,
        'protocol_version': 0x10,
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
        self.knx_destination = libknx.utils.knx_address_aton(address)

    def get_message(self):
        return self.message if self.message else False

    @staticmethod
    def get_host_ip_address():
        # TODO: remove this
        return socket.gethostbyname(socket.gethostname())

    @staticmethod
    def parse_knx_address(address):
        return '{}.{}.{}'.format((address >> 12) & 0xf, (address >> 8) & 0xf, address & 0xff)

    @staticmethod
    def parse_mac_address(address):
        return '{0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}'.format(*address)

    @staticmethod
    def parse_knx_device_serial(address):
        return '{0:02X}{1:02X}{2:02X}{3:02X}{4:02X}{5:02X}'.format(*address)

    def _pack_knx_header(self):
        try:
            return struct.pack('!BBHH',
                               self.header.get('header_length'),
                               self.header.get('protocol_version'),
                               self.header.get('service_type'),
                               self.header.get('total_length'))
        except struct.error as e:
            print(e)
            return False

    def _unpack_knx_header(self, message):
        """Set self.header dict and return message body"""
        try:
            self.header['header_length'], \
            self.header['protocol_version'], \
            self.header['service_type'], \
            self.header['total_length'] = struct.unpack('!BBHH', message[:6])
            return message[6:]
        except struct.error as e:
            print(e)
            return False


    def _unpack_stream(self, fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            print(e)
            return


    def _parse_knx_body_hpai(self, message):
        try:
            self.body['hpai'] = {}
            self.body['hpai']['structure_length'], \
            self.body['hpai']['protocol_code'], \
            self.body['hpai']['ip_address'], \
            self.body['hpai']['port'] = struct.unpack('!BBHH', message[:8])
            self.body['hpai']['ip_address'] = socket.inet_aton(self.body['hpai']['ip_address']) # most likely not works
            return message[8:]
        except struct.error as e:
            print(e)
            return False


class KnxSearchRequest(KnxMessage):

    def __init__(self, message=None, sockname=None):
        try:
            self.source, self.port = sockname
        except TypeError:
            self.source = None
            self.port = None

        if message:
            # parse a message
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            # create new message
            self.header['service_type'] = 0x0201
            self.header['total_length'] = 14
            #self.set_source_ip(self.get_host_ip_address())

    def pack_knx_message(self):
        self.message = self._pack_knx_header()
        self.message += self._pack_knx_body()

    def _pack_knx_body(self):
        self.body = struct.pack('!B', 8) # structure_length
        self.body += struct.pack('!B', 0x01) # protocol code
        self.body += socket.inet_aton(self.source)
        self.body += struct.pack('!H', self.port)
        return self.body

    def _unpack_knx_body(self, message):
        message = io.StringIO(message)
        try:
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['protocol_code'] = self._unpack_stream('!B', message)
            self.body['ip_address'] = socket.inet_ntoa(message.read(4))
            self.body['port'] = self._unpack_stream('!H', message)
        except Exception as e:
            print(e)


class KnxSearchResponse(KnxMessage):

    def __init__(self, message=None):
        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0202

    def pack_knx_message(self):
        pass

    def _pack_knx_body(self):
        pass

    def _unpack_knx_body(self, message):
        message = io.BytesIO(message)
        try:
            self.body['hpai'] = {}
            self.body['hpai']['structure_length'] = self._unpack_stream('!B', message)
            self.body['hpai']['protocol_code'] = self._unpack_stream('!B', message)
            self.body['hpai']['ip_address'] = socket.inet_ntoa(message.read(4))
            self.body['hpai']['port'] = self._unpack_stream('!H', message)

            self.body['dib_dev_info'] = {}
            self.body['dib_dev_info']['structure_length'] = self._unpack_stream('!B', message)
            self.body['dib_dev_info']['description_type'] = self._unpack_stream('!B', message)
            self.body['dib_dev_info']['knx_medium'] = self._unpack_stream('!B', message)
            self.body['dib_dev_info']['device_status'] = self._unpack_stream('!B', message)
            self.body['dib_dev_info']['knx_address'] = self.parse_knx_address(self._unpack_stream('!H', message))
            self.body['dib_dev_info']['project_install_identifier'] = self._unpack_stream('!H', message)
            self.body['dib_dev_info']['knx_device_serial'] = self._unpack_stream('!6s', message)
            self.body['dib_dev_info']['knx_dev_multicast_address'] = self._unpack_stream('!I', message)
            self.body['dib_dev_info']['knx_mac_address'] = self._unpack_stream('!6s', message)
            self.body['dib_dev_info']['device_friendly_name'] = self._unpack_stream('!30s', message)

            self.body['dib_supp_sv_families'] = {}
            self.body['dib_supp_sv_families']['structure_length'] = self._unpack_stream('!B', message)
            self.body['dib_supp_sv_families']['description_type'] = self._unpack_stream('!B', message)
            self.body['dib_supp_sv_families']['families'] = {}

            for i in range(int((self.body['dib_supp_sv_families']['structure_length']-2)/2)):
                service_id = self._unpack_stream('!B', message)
                version = self._unpack_stream('!B', message)
                self.body['dib_supp_sv_families']['families'][service_id] = {}
                self.body['dib_supp_sv_families']['families'][service_id]['version'] = version
        except Exception as e:
            print(e)


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
            #self.set_source_ip(self.get_host_ip_address())

    def pack_knx_message(self):
        self.message = self._pack_knx_header()
        self.message += self._pack_knx_body()

    def _pack_knx_body(self):
        self.body = struct.pack('!B', 8) # structure_length
        self.body += struct.pack('!B', 0x01) # protocol code
        self.body += socket.inet_aton(self.source)
        self.body += struct.pack('!H', self.port)
        return self.body

    def _unpack_knx_body(self, message):
        message = io.StringIO(message)
        try:
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['protocol_code'] = self._unpack_stream('!B', message)
            self.body['ip_address'] = socket.inet_ntoa(message.read(4))
            self.body['port'] = self._unpack_stream('H', message)
        except Exception as e:
            print(e)


class KnxDescriptionResponse(KnxMessage):

    def __init__(self, message=None):
        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0204

    def pack_knx_message(self):
        self.message = self._pack_knx_header()
        self.message += self._pack_knx_body()

    def _pack_knx_body(self):
        pass

    def _unpack_knx_body(self, message):
        message = io.BytesIO(message)
        try:
            self.body['dib_dev_info'] = {}
            self.body['dib_dev_info']['structure_length'] = self._unpack_stream('!B', message)
            self.body['dib_dev_info']['description_type'] = self._unpack_stream('!B', message)
            self.body['dib_dev_info']['knx_medium'] = self._unpack_stream('!B', message)
            self.body['dib_dev_info']['device_status'] = self._unpack_stream('!B', message)
            self.body['dib_dev_info']['knx_address'] = self.parse_knx_address(self._unpack_stream('!H', message))
            self.body['dib_dev_info']['project_install_identifier'] = self._unpack_stream('!H', message)
            self.body['dib_dev_info']['knx_device_serial'] = self.parse_knx_device_serial(self._unpack_stream('!6s', message))
            self.body['dib_dev_info']['knx_dev_multicast_address'] = socket.inet_ntoa(message.read(4))
            self.body['dib_dev_info']['knx_mac_address'] = self.parse_mac_address(self._unpack_stream('!6s', message))
            self.body['dib_dev_info']['device_friendly_name'] = self._unpack_stream('!30s', message)

            self.body['dib_supp_sv_families'] = {}
            self.body['dib_supp_sv_families']['structure_length'] = self._unpack_stream('!B', message)
            self.body['dib_supp_sv_families']['description_type'] = self._unpack_stream('!B', message)
            self.body['dib_supp_sv_families']['families'] = {}

            for i in range(int((self.body['dib_supp_sv_families']['structure_length']-2)/2)):
                service_id = self._unpack_stream('!B', message)
                version = self._unpack_stream('!B', message)
                self.body['dib_supp_sv_families']['families'][service_id] = {}
                self.body['dib_supp_sv_families']['families'][service_id]['version'] = version
        except Exception as e:
            print(e)


class KnxConnectionRequest(KnxMessage):

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
            #self.set_source_ip(self.get_host_ip_address())

    def pack_knx_message(self):
        self.message = self._pack_knx_header()
        self.message += self._pack_knx_body()

    def _pack_knx_body(self):
        # discovery endpoint
        self.body = struct.pack('!B', 8) # structure_length
        self.body += struct.pack('!B', 0x01) # protocol code
        self.body += socket.inet_aton(self.source)
        self.body += struct.pack('!H', self.port)
        # data endpoint
        self.body += struct.pack('!B', 8) # structure_length
        self.body += struct.pack('!B', 0x01) # protocol code
        self.body += socket.inet_aton(self.source)
        self.body += struct.pack('!H', self.port)
        # connection request information
        self.body += struct.pack('!B', 4) # structure_length
        self.body += struct.pack('!B', 0x04) # connection type
        self.body += struct.pack('!B', 0x02) # knx layer, TUNNEL_LINKLAYER
        self.body += struct.pack('!B', 0x00) # reserved
        return self.body

    def _unpack_knx_body(self, message):
        message = io.StringIO(message)
        try:
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['protocol_code'] = self._unpack_stream('!B', message)
            self.body['ip_address'] = socket.inet_ntoa(message.read(4))
            self.body['port'] = self._unpack_stream('H', message)

            self.body['data_endpoint'] = {}
            self.body['data_endpoint']['structure_length'] = self._unpack_stream('!B', message)
            self.body['data_endpoint']['protocol_code'] = self._unpack_stream('!B', message)
            self.body['data_endpoint']['ip_address'] = socket.inet_ntoa(message.read(4))
            self.body['data_endpoint']['port'] = self._unpack_stream('!H', message)

            self.body['connection_request_information'] = {}
            self.body['connection_request_information']['structure_length'] = self._unpack_stream('!B', message)
            self.body['connection_request_information']['connection_type'] = self._unpack_stream('!B', message)
            self.body['connection_request_information']['knx_layer'] = self._unpack_stream('!B', message)
            self.body['connection_request_information']['reserved'] = self._unpack_stream('!B', message)
        except Exception as e:
            print(e)


class KnxConnectionResponse(KnxMessage):
    ERROR = None

    def __init__(self, message=None):
        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0206
            self.header['total_length'] = 20
            #self.set_source_ip(self.get_host_ip_address())

    def pack_knx_message(self):
        pass

    def _pack_knx_body(self):
        pass

    def _unpack_knx_body(self, message):
        message = io.BytesIO(message)
        try:
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)

            if self.body['status'] != 0x00:
                # the device encountered an error!
                # TODO: implement some kind of retries and waiting periods
                self.ERROR = knx_status_codes[self.body['status']]
                print('KnxConnectionResponse ERROR: {}'.format(self.ERROR))
                return

            self.body['hpai'] = {}
            self.body['hpai']['structure_length'] = self._unpack_stream('!B', message)
            self.body['hpai']['protocol_code'] = self._unpack_stream('!B', message)
            self.body['hpai']['ip_address'] = socket.inet_ntoa(message.read(4))
            self.body['hpai']['port'] = self._unpack_stream('!H', message)

            self.body['data_block'] = {}
            self.body['data_block']['structure_length'] = self._unpack_stream('!B', message)
            self.body['data_block']['connection_type'] = self._unpack_stream('!B', message)
            self.body['data_block']['knx_address'] = self.parse_knx_address(self._unpack_stream('!H', message))
        except Exception as e:
            print(e)
            print(message.read())
            return


class KnxTunnellingRequest(KnxMessage):

    def __init__(self, message=None, port=None, communication_channel=None,
                 knx_source=None, knx_destination=None):
        self.port = port
        self.communication_channel = communication_channel

        # TODO: just for testing use fixed source/destination address
        #self.knx_source = knx_source
        #self.knx_destination = knx_destination
        self.knx_source = libknx.utils.knx_address_ntoa('0.0.0')
        self.knx_destination = libknx.utils.knx_address_ntoa('0.0.1')

        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0420
            self.header['total_length'] = 21
            #self.set_source_ip(self.get_host_ip_address())

    def pack_knx_message(self):
        self.message = self._pack_knx_header()
        self.message += self._pack_knx_body()

    def _pack_knx_body(self):
        # discovery endpoint
        self.body = struct.pack('!B', 4) # structure_length
        self.body += struct.pack('!B', self.communication_channel) # channel id
        self.body += struct.pack('!', 0) # sequence counter
        self.body += struct.pack('!B', 0) # reserved
        # cEMI (?)
        self.body += struct.pack('!B', 0x11) # message code
        self.body += struct.pack('!B', 0) # add information length
        self.body += struct.pack('!B', 0xbc) # controlfield 1
        self.body += struct.pack('!B', 0xf0) # controlfield 2
        self.body += struct.pack('!H', self.knx_source) # source address (KNX address)
        self.body += struct.pack('!H', self.knx_destination) # destination address (KNX address)
        self.body += struct.pack('!B', 0x01) # NPDU length
        self.body += struct.pack('!B', 0x00) # TPCI: UDT (?)
        self.body += struct.pack('!B', 0x81) # APCI (?)
        return self.body

    def _unpack_knx_body(self, message):
        message = io.StringIO(message)
        try:
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['sequence_counter'] = self._unpack_stream('!B', message)
            self.body['reserved'] = self._unpack_stream('!B', message)

            self.body['cemi'] = {}
            self.body['cemi']['message_code'] = self._unpack_stream('!B', message)
            self.body['cemi']['information_length'] = self._unpack_stream('!B', message)
            self.body['cemi']['controlfield_1'] = self._unpack_stream('!B', message)
            self.body['cemi']['controlfield_2'] = self._unpack_stream('!B', message)
            self.body['cemi']['knx_source'] = self._unpack_stream('!H', message)
            self.body['cemi']['knx_destination'] = self._unpack_stream('!H', message)
            self.body['cemi']['npdu'] = self._unpack_stream('!B', message)
            self.body['cemi']['tcpi'] = self._unpack_stream('!B', message)
            self.body['cemi']['apci'] = self._unpack_stream('!B', message)
        except Exception as e:
            print(e)


class KnxTunnellingAck(KnxMessage):

    def __init__(self, message=None):
        if message:
            message = self._unpack_knx_header(message)
            self._unpack_knx_body(message)
        else:
            self.header['service_type'] = 0x0421
            self.header['total_length'] = 10
            #self.set_source_ip(self.get_host_ip_address())

    def pack_knx_message(self):
        pass

    def _pack_knx_body(self):
        pass

    def _unpack_knx_body(self, message):
        message = io.BytesIO(message)
        try:
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['sequence_counter'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)
        except Exception as e:
            print(e)
            print(message.read())
            return