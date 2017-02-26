"""Tunnelling Services"""
import io
import struct
import logging

from knxmap import KNX_MESSAGE_TYPES
from .main import KnxMessage
from .cemi import CemiFrame
from .tp import ExtendedDataRequest

LOGGER = logging.getLogger(__name__)


class KnxTunnellingRequest(KnxMessage):
    def __init__(self, message=None, sockname=None, communication_channel=None,
                 knx_source=None, knx_destination=None, sequence_count=0,
                 message_code=0x11):
        super(KnxTunnellingRequest, self).__init__()
        self.cemi = CemiFrame()
        self.header['service_type'] = KNX_MESSAGE_TYPES.get('TUNNELLING_REQUEST')
        self.communication_channel = communication_channel
        self.sequence_count = sequence_count
        self.message_code = message_code
        if knx_source:
            self.set_knx_source(knx_source)
        if knx_destination:
            self.set_knx_destination(knx_destination)
        try:
            self.source, self.port = sockname
        except TypeError:
            self.source = None
            self.port = None
        if message:
            self.message = message
            self.unpack_knx_message(message)

    def _pack_knx_body(self, cemi=None):
        self.body = bytearray(struct.pack('!B', 4))  # structure_length
        self.body.extend(struct.pack('!B', self.communication_channel))
        self.body.extend(struct.pack('!B', self.sequence_count))
        self.body.extend(struct.pack('!B', 0))
        if cemi:
            self.body.extend(cemi)
        else:
            self.body.extend(self.cemi_frame)
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.structure_length = self._unpack_stream('!B', message)
            self.communication_channel = self._unpack_stream('!B', message)
            self.sequence_counter = self._unpack_stream('!B', message)
            self._unpack_stream('!B', message) # reserved
            # TODO: check what kind of data request it is?
            self.cemi.unpack_extended_data_request(message)
        except Exception as e:
            LOGGER.exception(e)

    # TODO: DEV CODE!

    def tpci_unnumbered_control_data(self, ucd_type):
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='UCD',
                                           tpci_control_type=ucd_type)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def tpci_numbered_control_data(self, ncd_type, sequence=0):
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NCD',
                                           tpci_sequence=sequence,
                                           tpci_control_type=ncd_type)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_device_descriptor_read(self, sequence=0):
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_DeviceDescriptor_Read')
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    # TODO: TEST
    def apci_individual_address_read(self, sequence=0):
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_IndividualAddress_Read')
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_authorize_request(self, sequence=0, key=0xffffffff):
        cemi = CemiFrame()
        cemi = cemi.pack()
        data = bytearray([0])
        data.extend(struct.pack('!I', key))
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_Authorize_Request',
                                           data=data)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_property_value_read(self, sequence=0, object_index=0, property_id=0x0f,
                                 num_elements=1, start_index=1):
        """A_PropertyValue_Read"""
        cemi = CemiFrame()
        cemi = cemi.pack()
        data = bytearray(struct.pack('!B', object_index))  # object index
        data.extend(struct.pack('!B', property_id))  # property id
        count_index = num_elements << 12
        count_index |= start_index << 0
        data.extend(struct.pack('!H', count_index))  # number of elements + start index
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_PropertyValue_Read',
                                           data=data)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_property_description_read(self, sequence=0, object_index=0, property_id=0x0f,
                                       num_elements=1, start_index=1):
        cemi = CemiFrame()
        cemi = cemi.pack()
        data = bytearray(struct.pack('!B', object_index))  # object index
        data.extend(struct.pack('!B', property_id))  # property id
        count_index = num_elements << 12
        count_index |= start_index << 0
        data.extend(struct.pack('!H', count_index))  # number of elements + start index
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_PropertyDescription_Read',
                                           data=data)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_user_manufacturer_info_read(self, sequence=0, channel=1, conversion_count=0x08):
        """A_UserManufacturerInfo_Read"""
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_UserManufacturerInfo_Read',
                                           apci_data=channel,
                                           data=conversion_count)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_adc_read(self, sequence=0):
        """A_ADC_Read"""
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_ADC_Read')
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

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
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_Memory_Read',
                                           apci_data=read_count,
                                           data=struct.pack('!H', memory_address))
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_memory_write(self, sequence=0, memory_address=0x0060, write_count=1,
                          data=b'\x00'):
        """A_Memory_Write"""
        cemi = CemiFrame()
        cemi = cemi.pack()
        data = bytearray(struct.pack('!B', memory_address))
        data.extend(struct.pack('!{}s'.format(len(data)), data))
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_Memory_Write',
                                           apci_data=write_count,
                                           data=data)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_key_write(self, sequence=0, level=0, key=0xffffffff):
        """A_Key_Write"""
        cemi = CemiFrame()
        cemi = cemi.pack()
        data = bytearray(struct.pack('!B', level))
        data.extend(struct.pack('!I', key))
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           tpci_sequence=sequence,
                                           apci_type='A_Key_Write',
                                           data=data)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    def apci_group_value_write(self, value=0):
        """A_GroupValue_Write"""
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           destination_type=1,
                                           tpci_type='UDP',
                                           apci_type='A_GroupValue_Write',
                                           apci_data=value)
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()

    # TODO: TEST
    def apci_restart(self, sequence=0):
        """A_Restart"""
        cemi = CemiFrame()
        cemi = cemi.pack()
        data_request = ExtendedDataRequest(knx_source=self.knx_source,
                                           knx_destination=self.knx_destination,
                                           tpci_type='NDP',
                                           apci_type='A_Restart')
        cemi.extend(data_request.pack())
        self.cemi_frame = cemi
        self.pack_knx_message()


class KnxTunnellingAck(KnxMessage):
    def __init__(self, message=None, communication_channel=None, sequence_count=0,
                 status=0):
        super(KnxTunnellingAck, self).__init__()
        self.header['service_type'] = KNX_MESSAGE_TYPES.get('TUNNELLING_ACK')
        self.communication_channel = communication_channel
        self.structure_length = 4
        self.sequence_count = sequence_count
        self.status = status
        if message:
            self.message = message
            self.unpack_knx_message(message)
        else:
            self.pack_knx_message()

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', self.structure_length))
        self.body.extend(struct.pack('!B', self.communication_channel))
        self.body.extend(struct.pack('!B', self.sequence_count))
        self.body.extend(struct.pack('!B', self.status))
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.structure_length = self._unpack_stream('!B', message)
            self.communication_channel = self._unpack_stream('!B', message)
            self.sequence_counter = self._unpack_stream('!B', message)
            self.status = self._unpack_stream('!B', message)
        except Exception as e:
            LOGGER.exception(e)
