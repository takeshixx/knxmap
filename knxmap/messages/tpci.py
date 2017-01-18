import struct
import logging

LOGGER = logging.getLogger(__name__)

from knxmap.data.constants import CEMI_TPCI_TYPES, _CEMI_TPCI_TYPES


class Tpci(object):
    def __init__(self, tpci_type=None, tpci_sequence=0,
                 data=None):
        if isinstance(tpci_type, str):
            tpci_type = CEMI_TPCI_TYPES.get(tpci_type)
        self.tpci_type = tpci_type
        self.sequence = tpci_sequence
        self.data = data
        self.status = None

    def __repr__(self):
        return '%s tpci_type: %s, sequence: %s, status: %s' % (
            self.__class__.__name__,
            _CEMI_TPCI_TYPES.get(self.tpci_type),
            self.sequence,
            self.status)

    @staticmethod
    def _unpack_stream(fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            LOGGER.exception(e)

    def pack(self):
        tpci = 0
        tpci |= self.sequence << 2
        tpci |= self.tpci_type << 6
        return tpci

    def unpack(self, data=None):
        data = data
        if data is None:
            data = self.data
        self.tpci_type = 0
        self.tpci_type |= ((data >> 6) & 1) << 0
        self.tpci_type |= ((data >> 7) & 1) << 1
        self.sequence = 0
        self.sequence |= ((data >> 2) & 1) << 0
        self.sequence |= ((data >> 3) & 1) << 1
        self.sequence |= ((data >> 4) & 1) << 2
        self.sequence |= ((data >> 5) & 1) << 3
        if self.tpci_type is [2, 3]:
            # Control data includes a status field
            self.status = 0
            self.status |= ((data >> 0) & 1) << 0
            self.status |= ((data >> 1) & 1) << 1
