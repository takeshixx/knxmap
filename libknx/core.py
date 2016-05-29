"""General core functionality that is needed for other modules,
including constants or package exceptions. This should only be
imported by other modules in this package."""
__all__ = ['KNX_CONSTANTS',
           'KNX_SERVICES',
           'KNX_MESSAGE_TYPES',
           'KNX_STATUS_CODES',
           'CEMI_PRIMITIVES',
           'CEMI_MESSAGE_CODES',  # TODO: maybe find a better solution instead of having the same dict twice
           'TPCI_TYPES',
           'APCI_TYPES',
           '_APCI_TYPES',
           'CEMI_PROPERTY_IDS',
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


_KNX_MESSAGE_TYPES = {
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
    0x0311: 'DEVICE_CONFIGURATION_RESPONSE',
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


KNX_MESSAGE_TYPES = {
    # KNXnet/IP Core
    'SEARCH_REQUEST': 0x0201,
    'SEARCH_RESPONSE': 0x0202,
    'DESCRIPTION_REQUEST': 0x0203,
    'DESCRIPTION_RESPONSE': 0x0204,
    'CONNECT_REQUEST': 0x0205,
    'CONNECT_RESPONSE': 0x0206,
    'CONNECTIONSTATE_REQUEST': 0x0207,
    'CONNECTIONSTATE_RESPONSE': 0x0208,
    'DISCONNECT_REQUEST': 0x0209,
    'DISCONNECT_RESPONSE': 0x020a,
    # KNXnet/IP Device Management
    'DEVICE_CONFIGURATION_REQUEST': 0x0310,
    'DEVICE_CONFIGURATION_RESPONSE': 0x0311,
    # KNXnet/IP Tunnelling
    'TUNNELLING_REQUEST': 0x0420,
    'TUNNELLING_ACK': 0x0421,
    # KNXnet/IP Routing
    'ROUTING_INDICATION': 0x0530,
    'ROUTING_LOST_MESSAGE': 0x0531,
    'ROUTING_BUSY': 0x0532,
    # KNXnet/IP Remote Configuration and Diagnosis
    'REMOTE_DIAGNOSTIC_REQUEST': 0x0740,
    'REMOTE_DIAGNOSTIC_RESPONSE': 0x0741,
    'REMOTE_BASIC_CONFIGURATION_REQUEST': 0x0742,
    'REMOTE_RESET_REQUEST': 0x0743,
    # KNXnet/IP ObjectServer
    'OBJECTSERVER_REQUEST': 0x0800}


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
    0x10: 'L_Raw.req',
    0x11: 'L_Data.req', # Request
    0x13: 'L_Poll_Data.req',
    0x25: 'L_Poll_Data.con',
    0x2e: 'L_Data.con', # Confirmation
    0x29: 'L_Data.ind', # Receive a data frame
    0x2b: 'L_Busmon.ind',
    0x2d: 'L_Raw.ind',
    0x2f: 'L_Raw.con',
    0xfb: 'M_PropRead.con',
    0xfc: 'M_PropRead.req'}


CEMI_MESSAGE_CODES = {
    'L_Raw.req': 0x10,
    'L_Data.req': 0x11, # Request
    'L_Poll_Data.req': 0x13,
    'L_Poll_Data.con': 0x25,
    'L_Data.con': 0x2e, # Confirmation
    'L_Data.ind': 0x29, # Receive a data frame
    'L_Busmon.ind': 0x2b,
    'L_Raw.ind': 0x2d,
    'L_Raw.con': 0x2f,
    'M_PropRead.con': 0xfb,
    'M_PropRead.req': 0xfc}


CEMI_PRIORITIES = {
    0x00: 'system',
    0x01: 'normal',
    0x02: 'urgent',
    0x03: 'low'}


COMM_TYPES = {
    0x00: 'Unnumbered Data Packet (UDT)',
    0x01: 'Numbered Data Packet (NDP)',
    0x02: 'Unnumbered Control Data (UCD)',
    0x03: 'Numbered Control Data (NCD)'}


TPCI_TYPES = {
    'UDP': 0x00,
    'NDT': 0x01,
    'UCD': 0x02,
    'NCD': 0x03}


_APCI_TYPES = {
    0x000: 'A_GroupValue_Read',
    0x001: 'A_GroupValue_Response',
    0x100: 'A_IndividualAddress_Read',
    0x140: 'A_IndividualAddress_Response',
    0x1c0: 'A_ADC_Response',
    0x1c4: 'A_SystemNetworkParameter_Read',
    0x1c9: 'A_SystemNetworkParameter_Response',
    0x1ca: 'A_SystemNetworkParameter_Write',
    0x002: 'A_GroupValue_Write',
    0x020: 'A_Memory_Read',
    0x024: 'A_Memory_Response',
    0x028: 'A_Memory_Write',
    0x2c0: 'A_UserMemory_Read',
    0x2c1: 'A_UserMemory_Response',
    0x2c2: 'A_UserMemory_Write',
    0x2c5: 'A_UserManufacturerInfo_Read',
    0x2c6: 'A_UserManufacturerInfo_Response',
    0x2c7: 'A_FunctionPropertyCommand',
    0x2c8: 'A_FunctionPropertyState_Read',
    0x2c9: 'A_FunctionPropertyState_Response',
    0x300: 'A_DeviceDescriptor_Read',
    0x340: 'A_DeviceDescriptor_Response',
    0x380: 'A_Restart',
    0x3d1: 'A_Authorize_Request',
    0x3d2: 'A_Authorize_Response',
    0x3d3: 'A_Key_Write',
    0x3d4: 'A_Key_Response',
    0x3d5: 'A_PropertyValue_Read',
    0x3d6: 'A_PropertyValue_Response',
    0x3d7: 'A_PropertyValue_Write',
    0x3d8: 'A_PropertyDescription_Read',
    0x3d9: 'A_PropertyDescription_Response',
    0x3da: 'A_NetworkParameter_Read',
    0x3db: 'A_NetworkParameter_Response',
    0x3dc: 'A_IndividualAddressSerialNumber_Read',
    0x3dd: 'A_IndividualAddressSerialNumber_Response',
    0x3df: 'A_IndividualAddressSerialNumber_Write',
    0x3e0: 'A_DomainAddress_Write',
    0x3e1: 'A_DomainAddress_Read',
    0x3e2: 'A_DomainAddress_Response',
    0x3e3: 'A_DomainAddressSelective_Read',
    0x3e4: 'A_NetworkParameter_Write',
    0x3e5: 'A_Link_Read',
    0x3e6: 'A_Link_Response',
    0x3e7: 'A_Link_Write',
    0x3e8: 'A_GroupPropValue_Read',
    0x3e9: 'A_GroupPropValue_Response',
    0x3ea: 'A_GroupPropValue_Write',
    0x3eb: 'A_GroupPropValue_InfoReport',
    0x3ec: 'A_DomainAddressSerialNumber_Read',
    0x3ed: 'A_DomainAddressSerialNumber_Response',
    0x3ee: 'A_DomainAddressSerialNumber_Write',
    0x3f0: 'A_FileStream_InforReport',
    0x006: 'A_ADC_Read',
    0x0c0: 'A_IndividualAddress_Write'}


APCI_TYPES = {
    'A_ADC_Read': 0x6,
    'A_ADC_Response': 0x1c0,
    'A_Authorize_Request': 0x3d1,
    'A_Authorize_Response': 0x3d2,
    'A_DeviceDescriptor_Read': 0x300,
    'A_DeviceDescriptor_Response': 0x340,
    'A_DomainAddressSelective_Read': 0x3e3,
    'A_DomainAddressSerialNumber_Read': 0x3ec,
    'A_DomainAddressSerialNumber_Response': 0x3ed,
    'A_DomainAddressSerialNumber_Write': 0x3ee,
    'A_DomainAddress_Read': 0x3e1,
    'A_DomainAddress_Response': 0x3e2,
    'A_DomainAddress_Write': 0x3e0,
    'A_FileStream_InforReport': 0x3f0,
    'A_FunctionPropertyCommand': 0x2c7,
    'A_FunctionPropertyState_Read': 0x2c8,
    'A_FunctionPropertyState_Response': 0x2c9,
    'A_GroupPropValue_InfoReport': 0x3eb,
    'A_GroupPropValue_Read': 0x3e8,
    'A_GroupPropValue_Response': 0x3e9,
    'A_GroupPropValue_Write': 0x3ea,
    'A_GroupValue_Read': 0x0,
    'A_GroupValue_Response': 0x1,
    'A_GroupValue_Write': 0x2,
    'A_IndividualAddressSerialNumber_Read': 0x3dc,
    'A_IndividualAddressSerialNumber_Response': 0x3dd,
    'A_IndividualAddressSerialNumber_Write': 0x3df,
    'A_IndividualAddress_Read': 0x100,
    'A_IndividualAddress_Response': 0x140,
    'A_IndividualAddress_Write': 0xc0,
    'A_Key_Response': 0x3d4,
    'A_Key_Write': 0x3d3,
    'A_Link_Read': 0x3e5,
    'A_Link_Response': 0x3e6,
    'A_Link_Write': 0x3e7,
    'A_Memory_Read': 0x20,
    'A_Memory_Response': 0x24,
    'A_Memory_Write': 0x28,
    'A_NetworkParameter_Read': 0x3da,
    'A_NetworkParameter_Response': 0x3db,
    'A_NetworkParameter_Write': 0x3e4,
    'A_PropertyDescription_Read': 0x3d8,
    'A_PropertyDescription_Response': 0x3d9,
    'A_PropertyValue_Read': 0x3d5,
    'A_PropertyValue_Response': 0x3d6,
    'A_PropertyValue_Write': 0x3d7,
    'A_Restart': 0x380,
    'A_SystemNetworkParameter_Read': 0x1c4,
    'A_SystemNetworkParameter_Response': 0x1c9,
    'A_SystemNetworkParameter_Write': 0x1ca,
    'A_UserManufacturerInfo_Read': 0x2c5,
    'A_UserManufacturerInfo_Response': 0x2c6,
    'A_UserMemory_Read': 0x2c0,
    'A_UserMemory_Response': 0x2c1,
    'A_UserMemory_Write': 0x2c2}


CEMI_PROPERTY_IDS = {
    'PID_ADDR_CHECK': 0x3d,
    'PID_ADDR_REPORT': 0x3c,
    'PID_APPLICATION': 0x40,
    'PID_DEVICE_ADDR': 0x3a,
    'PID_DEVICE_CONTROL': 0xe,
    'PID_DOMAIN_ADDR': 0x46,
    'PID_ERROR_FLAGS': 0x35,
    'PID_FIRMWARE_REVISION': 0x9,
    'PID_IO_LIST': 0x47,
    'PID_MANUFACTURER_ID': 0xc,
    'PID_MANUFACTURE_DATA': 0x13,
    'PID_MAX_APDULENGTH': 0x38,
    'PID_MAX_RETRY_COUNT ': 0x34,
    'PID_OBJECTADDRESS': 0x42,
    'PID_OBJECTLINK': 0x3f,
    'PID_OBJECT_TYPE': 0x1,
    'PID_OBJECT_VALUE': 0x3e,
    'PID_PARAMETER': 0x41,
    'PID_PB_CONFIG': 0x3b,
    'PID_PROGMODE': 0x36,
    'PID_PSU_STATUS': 0x44,
    'PID_PSU_TYPE': 0x43,
    'PID_ROUTING_COUNT': 0x33,
    'PID_SERIAL_NUMBER': 0xb,
    'PID_SERVICE_CONTROL': 0x8,
    'PID_SUBNET_ADDR': 0x39}


class Error(Exception):
    pass