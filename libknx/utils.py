def is_valid_knx_bus_address(address):
    try:
        parts = [int(i) for i in address.split('/')]

        if len(parts) is not 3:
            return False

        if (parts[0] < 0 or parts[0] > 15) or (parts[1] < 0 or parts[1] > 15):
            return False

        if parts[2] < 0 or parts[2] > 255:
            return False

        return True
    except:
        return False


def knx_address_ntoa(address):
    return '{}.{}.{}'.format((address >> 12) & 0xf, (address >> 8) & 0xf, address & 0xff)


def knx_address_aton(address):
    parts = address.split('.')
    return (int(parts[0]) << 12) + (int(parts[1]) << 8) + (int(parts[2]))
