import collections
import struct
import logging

from knxmap import CEMI_APCI_TYPES, TPCI_UNNUMBERED_CONTROL_DATA_TYPES, CEMI_MSG_CODES, CEMI_TPCI_TYPES, \
    TPCI_NUMBERED_CONTROL_DATA_TYPES

LOGGER = logging.getLogger(__name__)


class KnxCemiFrame(object):
    """Common External Message Interface (Common EMI, or cEMI) frame implementation.
    This is decoupled from the KnxMessage class because this allows
    to use cEMI frames over other mediums in the future (e.g. USB).

    Common EMI format:
     +--------+--------+-------- ... --------+---------------- ... ----------------+
     |Msg Code| AI Len |      Add. Info      |           Service Info              |
     +--------+--------+-------- ... --------+---------------- ... ----------------+
       1 byte   1 byte      [0..n] bytes                     n bytes
    """
    def __init__(self, message_code=None, knx_source=None, knx_destination=None):
        self.cemi_message_code = message_code
        self.knx_source = knx_source
        self.knx_destination = knx_destination

    @staticmethod
    def _unpack_stream(fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            LOGGER.exception(e)

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
        """Parse controlfield1 to a dict."""
        cf = {}
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
        """Parse controlfield2 to a dict."""
        cf = {}
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
        """Parse runstate field to a dict."""
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
        cemi = bytearray(struct.pack('!B', message_code))  # cEMI message code
        # TODO: implement variable length if additional information is included
        cemi.extend(struct.pack('!B', 0))  # add information length
        cemi.extend(struct.pack('!B', self.pack_cemi_cf1()))  # controlfield 1
        cemi.extend(struct.pack('!B', self.pack_cemi_cf2(*args, **kwargs)))  # controlfield 2
        cemi.extend(struct.pack('!H', self.knx_source))  # source address (KNX address)
        cemi.extend(struct.pack('!H', self.knx_destination))  # KNX destination address (either group or physical)
        return cemi

    def _unpack_cemi(self, message):
        cemi = {}
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

        tpci_unpacked = {}
        tpci = self._unpack_stream('!{}s'.format(cemi['npdu_len'] + 1), message)

        tpci_unpacked['tpci_type'] = 0
        tpci_unpacked['tpci_type'] |= ((tpci[0] >> 6) & 1) << 0
        tpci_unpacked['tpci_type'] |= ((tpci[0] >> 7) & 1) << 1
        tpci_unpacked['sequence'] = 0
        tpci_unpacked['sequence'] |= ((tpci[0] >> 2) & 1) << 0
        tpci_unpacked['sequence'] |= ((tpci[0] >> 3) & 1) << 1
        tpci_unpacked['sequence'] |= ((tpci[0] >> 4) & 1) << 2
        tpci_unpacked['sequence'] |= ((tpci[0] >> 5) & 1) << 3

        cemi['tpci'] = {}
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

            cemi['apci'] = {}
            cemi['apci']['type'] = tpci_unpacked['apci']
            cemi['apci']['data'] = tpci_unpacked.get('apci_data')
            cemi['data'] = tpci[2:]

        # TODO: if there is more data, read it now
        # TODO: read cemi['npdu_len']-1 bytes
        return cemi

    def tpci_unnumbered_control_data(self, ucd_type):
        assert ucd_type in TPCI_UNNUMBERED_CONTROL_DATA_TYPES.keys(), 'Invalid UCD type: {}'.format(ucd_type)
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 0))  # data length
        npdu = CEMI_TPCI_TYPES.get('UCD') << 14
        npdu |= TPCI_UNNUMBERED_CONTROL_DATA_TYPES.get(ucd_type) << 8
        cemi.extend(struct.pack('!H', npdu))
        return cemi

    def tpci_numbered_control_data(self, ncd_type, sequence=0):
        assert ncd_type in TPCI_NUMBERED_CONTROL_DATA_TYPES.keys(), 'Invalid NCD type: {}'.format(ncd_type)
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 0))  # data length
        npdu = CEMI_TPCI_TYPES.get('NCD') << 14
        npdu |= sequence << 10
        npdu |= TPCI_NUMBERED_CONTROL_DATA_TYPES.get(ncd_type) << 8
        cemi.extend(struct.pack('!H', npdu))
        return cemi

    def apci_device_descriptor_read(self, sequence=0):
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 1))  # data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_DeviceDescriptor_Read'] << 0
        cemi.extend(struct.pack('!H', npdu))
        return cemi

    def apci_individual_address_read(self, sequence=0):
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 1))  # data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_IndividualAddress_Read'] << 0
        cemi.extend(struct.pack('!H', npdu))
        return cemi

    def apci_authorize_request(self, sequence=0, key=0xffffffff):
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 6))  # data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_Authorize_Request'] << 0
        cemi.extend(struct.pack('!H', npdu))
        cemi.extend(struct.pack('!B', 0))  # reserved
        cemi.extend(struct.pack('!I', key))  # key
        return cemi

    def apci_property_value_read(self, sequence=0, object_index=0, property_id=0x0f,
                                 num_elements=1, start_index=1):
        """A_PropertyValue_Read"""
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 5))  # data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_PropertyValue_Read'] << 0
        cemi.extend(struct.pack('!H', npdu))
        cemi.extend(struct.pack('!B', object_index))  # object index
        cemi.extend(struct.pack('!B', property_id))  # property id
        count_index = num_elements << 12
        count_index |= start_index << 0
        cemi.extend(struct.pack('!H', count_index))  # number of elements + start index
        return cemi

    def apci_property_description_read(self, sequence=0, object_index=0, property_id=0x0f,
                                       num_elements=1, start_index=1):
        """A_PropertyDescription_Read"""
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 5))  # data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_PropertyDescription_Read'] << 0
        cemi.extend(struct.pack('!H', npdu))
        cemi.extend(struct.pack('!B', object_index))  # object index
        cemi.extend(struct.pack('!B', property_id))  # property id
        count_index = num_elements << 12
        count_index |= start_index << 0
        cemi.extend(struct.pack('!H', count_index))  # number of elements + start index
        return cemi

    def apci_user_manufacturer_info_read(self, sequence=0):
        """A_UserManufacturerInfo_Read"""
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 1))  # data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_UserManufacturerInfo_Read'] << 0
        cemi.extend(struct.pack('!H', npdu))
        return cemi

    def apci_adc_read(self, sequence=0):
        """A_ADC_Read"""
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 2))  # data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_ADC_Read'] << 0
        npdu |= 1 << 0  # channel no
        cemi.extend(struct.pack('!H', npdu))
        cemi.extend(struct.pack('!B', 0x08))  # data
        return cemi

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
        return cemi

    def apci_memory_write(self, sequence=0, memory_address=0x0060, write_count=1,
                          data=b'\x00'):
        """A_Memory_Write"""
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 3 + len(data)))  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_Memory_Write'] << 4
        npdu |= write_count << 0  # number of octets to read/write
        cemi.extend(struct.pack('!H', npdu))
        cemi.extend(struct.pack('!H', memory_address))  # memory address
        cemi.extend(struct.pack('!{}s'.format(len(data)), data))
        return cemi

    def apci_key_write(self, sequence=0, level=0, key=0xffffffff):
        """A_Key_Write"""
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 6))  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_Key_Write'] << 0
        cemi.extend(struct.pack('!H', npdu))
        cemi.extend(struct.pack('!B', level))
        cemi.extend(struct.pack('!I', key))
        return cemi

    def apci_group_value_write(self, value=0):
        """A_GroupValue_Write"""
        cemi = bytearray(self._pack_cemi(
            message_code=CEMI_MSG_CODES.get('L_Data.req'),
            address_type=True))
        cemi.extend(struct.pack('!B', 1))  # Data length
        npdu = CEMI_TPCI_TYPES.get('UDP') << 14
        npdu |= CEMI_APCI_TYPES['A_GroupValue_Write'] << 6
        npdu |= value << 0
        cemi.extend(struct.pack('!H', npdu))
        return cemi

    def apci_restart(self, sequence=0):
        """A_Restart"""
        cemi = bytearray(self._pack_cemi(message_code=CEMI_MSG_CODES.get('L_Data.req')))
        cemi.extend(struct.pack('!B', 1))  # Data length
        npdu = CEMI_TPCI_TYPES.get('NDP') << 14
        npdu |= sequence << 10
        npdu |= CEMI_APCI_TYPES['A_Restart'] << 0
        cemi.extend(struct.pack('!H', npdu))
        return cemi
