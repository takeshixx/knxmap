# Utilities to create KNX messages
import struct
import socket
import libknx.utils

__all__ = ['KnxSearchRequest', 'KnxConnectionRequest']


knx_message_types = {
    'search_request': '\x02\x01',
    'connection_request': '\x02\x05',
    'connection_response': '\x02\x06',
    'tunneling_request': '\x04\x20',
    'tunneling_ack': '\x03\x11'
}

knx_message_skeleton = [
    '\x06',              # head length - 1 byte
    '\x10',              # protocol version - 1 byte
    '{service_type}',    # service type a.k.a. message type - 2 bytes
    '{total_length}',    # total length - 2 bytes
    '{structure_length}',# structure length - 1 byte
    '\x01',              # host protocol code - 1 byte
    '{source}',          # source address - 4 bytes
    '\xff\xff',          # randomy bytes - 2 bytes
    '\x08',              # structure length 2 - 1 byte
    '\x01',              # host protocol code 2 - 1 byte
    '{destination}',     # destination address - 4 bytes
    '\xff\xff',          # random bytes 2 - 2 bytes
    '\x02',              # structure length 3 - 1 byte
    '\x04'               # connection type - 1 byte
]

class KnxMessage(object):
    message = None

    def set_source_ip(self, address):
        if libknx.utils.is_valid_knx_bus_address(address):
            self.source = socket.inet_aton(address)

    def set_destination_ip(self, address):
        if libknx.utils.is_valid_knx_bus_address(address):
            self.destination = socket.inet_aton(address)

    def get_message(self):
        return self.message if self.message else False

    @staticmethod
    def get_host_ip_address():
        # TODO: Implement more reliable method, maybe with iproute2 tools
        return socket.gethostbyname(socket.gethostname())


class KnxSearchRequest(KnxMessage):
    knx_message_skeleton = [
        # header
        '\x06',              # head length - 1 byte
        '\x10',              # protocol version - 1 byte
        '{service_type}',    # service type a.k.a. message type - 2 bytes
        '{total_length}',    # total length - 2 bytes
        # body
        '{structure_length}',# structure length - 1 byte
        '\x01',              # host protocol code - 1 byte
        '{source}',          # source address - 4 bytes
        '{port}'             # randomy bytes - 2 bytes
    ]

    def __init__(self, source=None, port=55290):
        self.type = knx_message_types.get('search_request')
        self.total_length = struct.pack('>I', 14)
        self.structure_length = struct.pack('>I', 8)
        self.port = struct.pack('>I', port)

        if source:
            self.set_source_ip(source)
        else:
            self.set_source_ip(self.get_host_ip_address())

        if self.source:
            self.prepare_message()

    def prepare_message(self):
        self.message = self.knx_message_skeleton.format(
            service_type=self.type,
            total_length=self.total_length,
            structure_length=self.structure_length,
            source=self.source,
            port=self.port
        )


class KnxConnectionRequest(KnxMessage):
    knx_message_skeleton = [
        # header
        '\x06',              # head length - 1 byte
        '\x10',              # protocol version - 1 byte
        '{service_type}',    # service type a.k.a. message type - 2 bytes
        '{total_length}',    # total length - 2 bytes
        # body
        # discovery endpoint
        '\x08',              # structure length - 1 byte
        '\x01',              # host protocol code - 1 byte
        '{source}',          # source address - 4 bytes
        '{port}',
        # data endpoint
        '\x08',              # structure length - 1 byte
        '\x01',              # host protocol - 1 byte
        '{source}',
        '{endpoint_port}',
        # connection request information
        '\x04',              # structure length
        '\x04',              # connection type
        '\x02',             # KNX layer
        '\x00'              # reserved
    ]

    def __init__(self, port=55291):
        self.type = knx_message_types.get('connection_request')
        self.total_length = struct.pack('>I', 26)

        self.set_source_ip(self.get_host_ip_address())
        self.port = struct.pack('>I', port)
        self.endpoint_port = struct.pack('>I', port+1)


    def prepare_message(self):
        self.message = self.knx_message_skeleton.format(
            service_type=self.type,
            total_length=self.total_length,
            source=self.source,
            port=self.port,
            endpoint_port=self.endpoint_port
        )