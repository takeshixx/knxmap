# Placeholder for all the packages
import struct
import knxlib.utils

__all__ = ['KnxMessage']


knx_message_types = {
    'connection_request': '\x02\x05',
    'connection_response': '\x02\x06',
    'tunneling_request': '\x04\x20',
    'tunneling_ack': '\x03\x11'
}

knx_message_skeleton = [
    '\x06',              # head length - 1 byte
    '\x10',              # protocol version - 1 byte
    '{service_type}',    # service type a.k.a. message type - 2 bytes
    '\x00\x18',          # total length - 2 bytes
    '\x08',              # structure length - 1 byte
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

    def __init__(self, type, source=None, destination=None):
        if type in knx_message_types:
            self.type = knx_message_types.get(type)

        self.set_source_ip(source)
        self.set_destination_ip(destination)

        if self.source and self.destination:
            self.prepare_message()


    def set_source_ip(self, address):
        if knxlib.utils.is_valid_knx_bus_address(address):
            # TODO: Add proper address format
            _address = struct.pack('>I', 'asd')
            self.source = _address


    def set_destination_ip(self, address):
        if knxlib.utils.is_valid_knx_bus_address(address):
            # TODO: Add proper address format
            _address = struct.pack('>I', 'asd')
            self.destination = _address


    def prepare_message(self):
        self.message = knx_message_skeleton.format(
            service_type=self.type,
            source=self.source,
            destination=self.destination
        )
