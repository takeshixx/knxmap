"""Tunnelling Services"""
import io
import struct
import logging

from knxmap import KNX_MESSAGE_TYPES
from knxmap.messages.main import KnxMessage
from knxmap.messages.cemi import KnxCemiFrame

LOGGER = logging.getLogger(__name__)


class KnxTunnellingRequest(KnxMessage):
    def __init__(self, message=None, sockname=None, communication_channel=None,
                 knx_source=None, knx_destination=None, sequence_count=0, message_code=0x11):
        super(KnxTunnellingRequest, self).__init__()
        if message:
            self.cemi = KnxCemiFrame()
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('TUNNELLING_REQUEST')
            self.communication_channel = communication_channel
            self.sequence_count = sequence_count
            if knx_source:
                self.set_knx_source(knx_source)
            if knx_destination:
                self.set_knx_destination(knx_destination)
            self.cemi = KnxCemiFrame(message_code=message_code,
                                     knx_source=self.knx_source,
                                     knx_destination=self.knx_destination)
            self.cemi_frame = bytearray()
            try:
                self.source, self.port = sockname
            except TypeError:
                self.source = None
                self.port = None

    def _pack_knx_body(self, cemi=None):
        self.body = bytearray(struct.pack('!B', 4))  # structure_length
        self.body.extend(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', self.sequence_count))  # sequence counter
        self.body.extend(struct.pack('!B', 0))  # reserved
        if cemi:
            self.body.extend(cemi)
        else:
            self.body.extend(self.cemi_frame)
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['sequence_counter'] = self._unpack_stream('!B', message)
            self.body['reserved'] = self._unpack_stream('!B', message)
            self.body['cemi'] = self.cemi._unpack_cemi(message)
        except Exception as e:
            LOGGER.exception(e)

    def tpci_unnumbered_control_data(self, ucd_type):
        self.cemi_frame = self.cemi.tpci_unnumbered_control_data(ucd_type)
        self.pack_knx_message()

    def tpci_numbered_control_data(self, ncd_type, sequence=0):
        self.cemi_frame = self.cemi.tpci_numbered_control_data(ncd_type, sequence=sequence)
        self.pack_knx_message()

    def apci_device_descriptor_read(self, sequence=0):
        self.cemi_frame = self.cemi.apci_device_descriptor_read(sequence=sequence)
        self.pack_knx_message()

    def apci_individual_address_read(self, sequence=0):
        self.cemi_frame = self.cemi.apci_individual_address_read(sequence=sequence)
        self.pack_knx_message()

    def apci_authorize_request(self, sequence=0, key=0xffffffff):
        self.cemi_frame = self.cemi.apci_authorize_request(sequence=sequence, key=key)
        self.pack_knx_message()

    def apci_property_value_read(self, sequence=0, object_index=0, property_id=0x0f,
                                 num_elements=1, start_index=1):
        """A_PropertyValue_Read"""
        self.cemi_frame = self.cemi.apci_property_value_read(sequence=sequence, object_index=object_index,
                                                             property_id=property_id, num_elements=num_elements,
                                                             start_index=start_index)
        self.pack_knx_message()

    def apci_property_description_read(self, sequence=0, object_index=0, property_id=0x0f,
                                       num_elements=1, start_index=1):
        """A_PropertyDescription_Read"""
        self.cemi_frame = self.cemi.apci_property_description_read(sequence=sequence, object_index=object_index,
                                                                   property_id=property_id, num_elements=num_elements,
                                                                   start_index=start_index)
        self.pack_knx_message()

    def apci_user_manufacturer_info_read(self, sequence=0):
        """A_UserManufacturerInfo_Read"""
        self.cemi_frame = self.cemi.apci_user_manufacturer_info_read(sequence=sequence)
        self.pack_knx_message()

    def apci_adc_read(self, sequence=0):
        """A_ADC_Read"""
        self.cemi_frame = self.cemi.apci_adc_read(sequence=sequence)
        self.pack_knx_message()

    def apci_memory_read(self, sequence=0, memory_address=0x0060, read_count=1):
        """A_Memory_Read"""
        self.cemi_frame = self.cemi.apci_memory_read(sequence=sequence, memory_address=memory_address,
                                                     read_count=read_count)
        self.pack_knx_message()

    def apci_memory_write(self, sequence=0, memory_address=0x0060, write_count=1,
                          data=b'\x00'):
        """A_Memory_Write"""
        self.cemi_frame = self.cemi.apci_memory_write(sequence=sequence, memory_address=memory_address,
                                                      write_count=write_count, data=data)
        self.pack_knx_message()

    def apci_key_write(self, sequence=0, level=0, key=0xffffffff):
        """A_Key_Write"""
        self.cemi_frame = self.cemi.apci_key_write(sequence=sequence, level=level, key=key)
        self.pack_knx_message()

    def apci_group_value_write(self, value=0):
        """A_GroupValue_Write"""
        self.cemi_frame = self.cemi.apci_group_value_write(value=value)
        self.pack_knx_message()

    def apci_restart(self, sequence=0):
        """A_Restart"""
        self.cemi_frame = self.cemi.apci_restart(sequence=sequence)
        self.pack_knx_message()


class KnxTunnellingAck(KnxMessage):
    def __init__(self, message=None, communication_channel=None, sequence_count=0):
        super(KnxTunnellingAck, self).__init__()
        if message:
            self.unpack_knx_message(message)
        else:
            self.header['service_type'] = KNX_MESSAGE_TYPES.get('TUNNELLING_ACK')
            self.communication_channel = communication_channel
            self.sequence_count = sequence_count
            self.pack_knx_message()

    def _pack_knx_body(self):
        self.body = bytearray(struct.pack('!B', 4))  # structure_length
        self.body.extend(struct.pack('!B', self.communication_channel))  # channel id
        self.body.extend(struct.pack('!B', self.sequence_count))  # sequence counter
        self.body.extend(struct.pack('!B', 0))  # status
        return self.body

    def _unpack_knx_body(self, message):
        try:
            message = io.BytesIO(message)
            self.body['structure_length'] = self._unpack_stream('!B', message)
            self.body['communication_channel_id'] = self._unpack_stream('!B', message)
            self.body['sequence_counter'] = self._unpack_stream('!B', message)
            self.body['status'] = self._unpack_stream('!B', message)
        except Exception as e:
            LOGGER.exception(e)
