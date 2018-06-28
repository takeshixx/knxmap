import collections
import struct
import logging
import io

from .tp import ExtendedDataRequest

LOGGER = logging.getLogger(__name__)

class CemiFrame(object):
    """Common External Message Interface (Common EMI, or cEMI) frame implementation.
    This is decoupled from the KnxMessage class because this allows
    to use cEMI frames over other mediums in the future (e.g. USB).

    Common EMI format:
     +--------+--------+-------- ... --------+---------------- ... ----------------+
     |Msg Code| AI Len |      Add. Info      |           Service Info              |
     +--------+--------+-------- ... --------+---------------- ... ----------------+
       1 byte   1 byte      [0..n] bytes                     n bytes
    """
    def __init__(self, message_code=0x11, additional_information_len=0,
                 additional_information=None):
        self.message_code = message_code
        self.additional_information_len = additional_information_len
        self.additional_information = additional_information or bytearray()
        self.raw_frame = bytearray()
        self.control_field = None
        self.extended_control_field = None
        self.knx_source = None
        self.knx_destination = None
        self.npdu_len = None
        self.tpci = None
        self.apci = None

    @staticmethod
    def _unpack_stream(fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            if not buf:
                # In case we already reached EOF
                # just return an empty byte string.
                return b''
            if len(buf) != struct.calcsize(fmt):
                # If read() returned some bytes, but
                # not as much as required by fmt,
                # unpack only the available bytes.
                fmt = '!{}s'.format(len(buf))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            LOGGER.exception(e)

    def pack(self, message_code=None):
        message_code = message_code if message_code else self.message_code
        cemi = bytearray(struct.pack('!B', message_code))  # cEMI message code
        # TODO: implement variable length if additional information is included
        cemi.extend(struct.pack('!B', self.additional_information_len))  # add information length
        if self.additional_information_len:
            cemi.extend(self.additional_information)
        return cemi

    def unpack(self, message):
        self.message_code = self._unpack_stream('!B', message)
        self.additional_information_len = self._unpack_stream('!B', message)

    def unpack_extended_data_request(self, message):
        """This function provides message parsing that
        is mostly compatible with the old API."""
        self.unpack(message)
        if self.message_code == 0x2b and \
                self.additional_information_len > 0: # L_Busmon.ind
            additional_information = io.BytesIO(self._unpack_stream('!{}s'.format(
                self.additional_information_len), message))
            self.additional_information = {}
            self.additional_information['type1'] = self._unpack_stream('!B', additional_information)
            self.additional_information['type1_length'] = self._unpack_stream('!B', additional_information)
            self.additional_information['error_flags'] = self._unpack_stream('!B', additional_information)
            self.additional_information['type2'] = self._unpack_stream('!B', additional_information)
            self.additional_information['type2_length'] = self._unpack_stream('!B', additional_information)
            self.additional_information['timestamp'] = self._unpack_stream('!4s', additional_information)
            self.raw_frame.extend(message.read())
        else:
            data_request = ExtendedDataRequest(message=message)
            self.control_field = data_request.control_field
            self.extended_control_field = data_request.extended_control_field
            self.knx_source = data_request.knx_source
            self.knx_destination = data_request.knx_destination
            self.npdu_len = data_request.npdu_len
            self.tpci = data_request.tpci
            self.apci = data_request.apci
            self.data = data_request.data

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
