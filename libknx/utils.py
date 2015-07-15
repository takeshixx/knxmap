def is_valid_knx_bus_address(address):
    try:
        parts = [int(i) for i in address.split('/')]

        if len(parts) is not 3:
            return False

        if (parts[0]<0 or parts[0] > 15) or (parts[1]<0 or parts[1]>15):
            return False

        if  parts[2]<0 or parts[2]>255:
            return False

        return True
    except:
        return False