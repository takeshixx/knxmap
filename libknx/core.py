"""General core functionality that is needed for other modules,
including constants or package exceptions. This should only be
imported by other modules in this package."""
__all__ = ['KNX_CONSTANTS',
           'KNX_SERVICES',
           'KNX_MESSAGE_TYPES',
           'KNX_STATUS_CODES',
           'CEMI_PRIMITIVES',
           'Error']


KNX_CONSTANTS = {
    'KNXNETIP_VERSION_10': 0x10,
    'HEADER_SIZE_10': 0x06}


KNX_SERVICES = {
    0x02: 'KNXnet/IP Core',
    0x03: 'KNXnet/IP Device Management',
    0x04: 'KNXnet/IP Tunnelling',
    0x05: 'KNXnet/IP Routing',
    0x06: 'KNXnet/IP Remote Logging',
    0x07: 'KNXnet/IP Remote Configuration and Diagnosis',
    0x08: 'KNXnet/IP Object Server'}


KNX_MESSAGE_TYPES = {
    # KNXnet/IP Core
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
    # KNXnet/IP Device Management
    0x0310: 'DEVICE_CONFIGURATION_REQUEST',
    0x0311: 'DEVICE_CONFIGURATION_REQUEST',
    # KNXnet/IP Tunnelling
    0x0420: 'TUNNELLING_REQUEST',
    0x0421: 'TUNNELLING_ACK',
    # KNXnet/IP Routing
    0x0530: 'ROUTING_INDICATION',
    0x0531: 'ROUTING_LOST_MESSAGE',
    0x0532: 'ROUTING_BUSY',
    # KNXnet/IP Remote Configuration and Diagnosis
    0x0740: 'REMOTE_DIAGNOSTIC_REQUEST',
    0x0741: 'REMOTE_DIAGNOSTIC_RESPONSE',
    0x0742: 'REMOTE_BASIC_CONFIGURATION_REQUEST',
    0x0743: 'REMOTE_RESET_REQUEST',
    # KNXnet/IP ObjectServer
    0x0800: 'OBJECTSERVER_REQUEST'}


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


# See: http://www.openremote.org/display/knowledge/Common+External+Message+Interface+(cEMI)
CEMI_PRIMITIVES = {
    0x11: 'L_Data.req', # Request
    0x2e: 'L_Data.con', # Confirmation
    0x29: 'L_Data.ind'}  # Receive a data frame


CEMI_PRIORITIES = {
    0x00: 'system',
    0x01: 'normal',
    0x02: 'urgent',
    0x03: 'low'}


COMM_TYPES = {
    0x00: 'Unnumbered Data Packet (UDP)',
    0x01: 'Numbered Data Packet (NDP)',
    0x02: 'Unnumbered Control Data (UCD)',
    0x03: 'Numbered Control Data (NCD)'}


APCI = {0x00: 'GroupValueRead',
        0x01: 'GroupValueResponse',
        0x02: 'GroupValueWrite',
        0x03: 'IndividualAddrWrite',
        0x04: 'IndividualAddrRequest',
        0x05: 'IndividualAddrResponse',
        0x06: 'AdcRead',
        0x07: 'AdcResponse',
        0x08: 'MemoryRead',
        0x09: 'MemoryResponse',
        0x0a: 'MemoryWrite',
        0x0b: 'UserMessage',
        0x0c: 'MaskVersionRead',
        0x0d: 'MaskVersionResponse',
        0x0e: 'Restart',
        0x0f: 'Escape'}


class Error(Exception):
    pass