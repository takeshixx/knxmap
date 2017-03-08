import json
import socket
import collections

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
    assert isinstance(address, int), 'Address should be an integer, got %s instead' % type(address)
    return '{}.{}.{}'.format((address >> 12) & 0xf, (address >> 8) & 0xf, address & 0xff)


def pack_knx_address(address):
    """Pack physical/individual KNX address.

    pack_knx_address('15.15.255')
    65535
    """
    assert isinstance(address, str), 'Address should be a string, got %s instead' % type(address)
    parts = address.split('.')
    return (int(parts[0]) << 12) + (int(parts[1]) << 8) + (int(parts[2]))


def parse_knx_group_address(address):
    """Parse KNX group address.

    parse_knx_group_address(12345)
    '6/0/57'
    """
    assert isinstance(address, int), 'Address should be an integer, got %s instead' % type(address)
    return '{}/{}/{}'.format((address >> 11) & 0x1f, (address >> 8) & 0x7, address & 0xff)


def pack_knx_group_address(address):
    """Pack KNX group address.

    pack_knx_group_address('6/0/57')
    12345
    """
    assert isinstance(address, str), 'Address should be a string, got %s instead' % type(address)
    parts = address.split('/')
    return (int(parts[0]) << 11) + (int(parts[1]) << 8) + (int(parts[2]))


def parse_knx_device_serial(address):
    """Parse a KNX device serial to human readable format.

    parse_knx_device_serial(b'\x00\x00\x00\x00\X12\x23')
    '000000005C58'
    """
    assert isinstance(address, bytes), 'Address should be bytes, got %s instead' % type(address)
    return '{0:02X}{1:02X}{2:02X}{3:02X}{4:02X}{5:02X}'.format(*address)


def parse_mac_address(address):
    """Parse a MAC address to human readable format.

    parse_mac_address(b'\x12\x34\x56\x78\x90\x12')
    '12:34:56:78:90:12'
    """
    assert isinstance(address, bytes), 'Address should be bytes, got %s instead' % type(address)
    return '{0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}'.format(*address)


def parse_device_descriptor(desc):
    """Parse device descriptors to three separate integers.

    parse_device_descriptor(1793)
    (0, 112, 1)
    """
    assert isinstance(desc, int), 'Device descriptor is not an integer, got %s instead' % type(desc)
    desc = format(desc, '04x')
    medium = int(desc[0])
    dev_type = int(desc[1:-1], 16)
    version = int(desc[-1])
    return medium, dev_type, version


def unpack_ip_address(address):
    return socket.inet_aton(address)


def get_manufacturer_by_id(mid):
    assert isinstance(mid, int)
    with open('knxmap/data/manufacturers.json', 'rb') as f:
        m = json.load(f)
        for _m in m.get('manufacturers'):
            if int(_m.get('knx_manufacturer_id')) == mid:
                return _m.get('name')


def make_runstate_printable(runstate):
    _runstate = collections.OrderedDict()
    if isinstance(runstate, bytes):
        runstate = unpack_cemi_runstate(runstate)
    for k, v in runstate.items():
        if k == 'PROG_MODE':
            _runstate['Programming Mode'] = 'ENABLED' if v else 'disabled'
        elif k == 'LINK_LAYER':
            _runstate['Link Layer'] = 'ENABLED' if v else 'disabled'
        elif k == 'TRANSPORT_LAYER':
            _runstate['Transport Layer'] = 'ENABLED' if v else 'disabled'
        elif k == 'APP_LAYER':
            _runstate['Application Layer'] = 'ENABLED' if v else 'disabled'
        elif k == 'SERIAL_INTERFACE':
            _runstate['Serial Interface'] = 'ENABLED' if v else 'disabled'
        elif k == 'USER_APP':
            _runstate['User Application'] = 'ENABLED' if v else 'disabled'
        elif k == 'BC_DM':
            _runstate['BC DM'] = v
    return _runstate


def unpack_cemi_runstate(data):
    """Parse runstate field to a dict."""
    if isinstance(data, bytes):
        data = int.from_bytes(data, 'big')
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
