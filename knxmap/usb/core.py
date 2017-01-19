import io
import struct
import time
import logging

try:
    import hid
except ImportError:
    pass

from knxmap.data.constants import CEMI_APCI_TYPES, EMI1_PRIMITIVES
from knxmap.messages import DataRequest

LOGGER = logging.getLogger(__name__)

PROTOCOL_TYPES = {0x01: 'KNX_TUNNEL',
                  0x02: 'M_BUS_TUNNEL',
                  0x03: 'BATIBUS_TUNNEL',
                  0x0f: 'BUS_ACCESS_SERVER'} # DEVICE FEATURE PROTOCOL

EMI_ID_ENUM = {0x01: 'EMI1',
               0x02: 'EMI2',
               0x03: 'cEMI'}

# Only apply to DEVICE FEATURE PROTOCOL
DEVICE_SERVICE_IDENTIFIERS = {0x01: 'FEATURE_QUERY',
                              0x02: 'FEATURE_RESPONSE',
                              0x03: 'FEATURE_SET',
                              0x04: 'FEATURE_INFO'}

DEVICE_FEATURES = {0x01: 'SUPPORTED_EMI_TYPE',
                   0x02: 'HOST_DEVICE_DESCRIPTOR_TYPE',
                   0x03: 'BUS_CONNECTION_STATUS',
                   0x04: 'KNX_MANUFACTURER_CODE',
                   0x05: 'ACTIVE_EMI_TYPE'}


class KnxUsbTransport(object):
    def __init__(self, vendor_id=None, product_id=None):
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.emi_version = None
        self._dev = hid.device()
        self._dev.open(self.vendor_id, self.product_id)
        self._dev.set_nonblocking(1)
        self.serial = self._dev.get_serial_number_string()
        active_emi = self._get_active_emi_type()
        if active_emi:
            self.emi_version = active_emi
        else:
            self._get_supported_emi_type()
            self._set_emi_type()
        self._check_bus_connection_status()
        self._get_device_descriptor()
        self.init_connection()
        self._check_bus_connection_status()

    def _get_supported_emi_type(self):
        LOGGER.debug('Getting supported USB EMI types')
        report = KnxHidReport()
        frame = report.get_supported_emi_types_report()
        LOGGER.trace_outgoing(report)
        self.write(frame)
        time.sleep(0.05)
        resp = self.read()
        assert resp, 'Response report is empty'
        report = KnxHidReport(data=resp)
        LOGGER.trace_incoming(report)
        self.emi_version = report.body.get('data')[1]

    def _set_emi_type(self):
        LOGGER.debug('Setting USB EMI type')
        report = KnxHidReport()
        frame = report.set_emi_type_report(emi_type=self.emi_version)
        LOGGER.trace_outgoing(report)
        self.write(frame)
        time.sleep(0.05)
        resp = self.read()
        assert resp, 'Response report is empty'
        report = KnxHidReport(data=resp)
        LOGGER.trace_incoming(report)
        if report.body.get('data'):
            print(report.body.get('data'))

    def _get_device_descriptor(self):
        LOGGER.debug('Trying to read USB device descriptor')
        report = KnxHidReport(protocol_id=0x0f,
                              message_code=0x02)
        frame = report.report
        LOGGER.trace_outgoing(report)
        self.write(frame)
        time.sleep(0.05)
        resp = self.read()
        assert resp, 'Response report is empty'
        report = KnxHidReport(data=resp)
        LOGGER.trace_incoming(report)
        if report.body.get('data'):
            print('device descriptor')
            print(report.body.get('data'))

    def _get_active_emi_type(self):
        LOGGER.debug('Trying to read active USB EMI type')
        report = KnxHidReport(protocol_id=0x0f,
                              message_code=0x05)
        frame = report.report
        LOGGER.trace_outgoing(report)
        self.write(frame)
        time.sleep(0.05)
        resp = self.read()
        assert resp, 'Response report is empty'
        report = KnxHidReport(data=resp)
        LOGGER.trace_incoming(report)
        if report.body.get('data'):
            return report.body.get('data')[0]

    def _check_bus_connection_status(self):
        LOGGER.debug('Checking USB bus connection status')
        report = KnxHidReport()
        frame = report.get_bus_connection_status()
        LOGGER.trace_outgoing(report)
        self.write(frame)
        time.sleep(0.05)
        resp = self.read()
        assert resp, 'Response report is empty'
        report = KnxHidReport(data=resp)
        LOGGER.trace_incoming(report)
        if report.body.get('data')[0] != 1:
            LOGGER.error('There might be something wrong with the bus connection!')

    def init_connection(self):
        LOGGER.debug('Initialization USB bus connection')
        """Activates EMI type?"""
        init = bytearray([0x01, 0x13, 0x0a, 0x00, 0x08,
                          0x00, 0x02, 0x0f, 0x03, 0x00,
                          0x00, 0x05, 0x01])
        # TODO: which one is correct?
        #initasd = bytearray([0x01, 0x13, 0x0d, 0x00, 0x08,
        #                  0x00, 0x05, 0x01, 0x01, 0x00,
        #                  0x00, 0x46, 0x01, 0x00, 0x60,
        #                  0x12])
        init[12] = self.emi_version
        init.extend([0] * (64 - len(init)))
        report = KnxHidReport(data=init)
        LOGGER.trace_outgoing(report)
        self.write(init)
        time.sleep(0.5)

    def write(self, data):
        return self._dev.write(data)

    def read(self, size=64):
        return self._dev.read(size)


class KnxHidReport(object):
    def __init__(self, data=None, frame=None, protocol_id=0x0f, emi_id=0x01,
                 message_code=0x11):
        self._report = bytearray()
        self.report_header = {'report_id': 0x01,
                              'package_info': 0x13,
                              'data_length': 0x00}
        self.protocol_header = {'protocol_version': 0x00,
                                'header_length': 0x08,
                                'body_length': 0x00, # 2 bytes
                                'protocol_id': protocol_id, # 0x0f for USB dev, 0x01 for KNX
                                'emi_id': emi_id,
                                'manufacturer_code': 0x00} # 2 bytes
        self.body = {'message_code': message_code,
                     'data': bytearray(),
                     'frame': frame}
        if data:
            assert len(data) == 64
            if isinstance(data, list):
                data = io.BytesIO(bytearray(data))
            elif isinstance(data, bytearray):
                data = io.BytesIO(data)
            else:
                LOGGER.error('Invalid data type %s' % type(data))
            self._unpack_report_and_protocol_header(data)
            if (self.report_header.get('data_length') - 8) > 0:
                # parse data
                self._unpack_report_body(data)

    def __repr__(self):
        if self.protocol_header.get('protocol_id') == 0x0f:
            return '%s protocol_type: %s, device_feature: %s, service_identifier: %s, ' \
                   'message_code: %s' % (
                       self.__class__.__name__,
                       PROTOCOL_TYPES.get(self.protocol_header.get('protocol_id')),
                       DEVICE_FEATURES.get(self.body.get('message_code')),
                       DEVICE_SERVICE_IDENTIFIERS.get(self.protocol_header.get('emi_id')),
                       hex(self.body.get('message_code')))
        else:
            return '%s protocol_type: %s, message_type: %s, service_identifier: %s, ' \
                   'message_code: %s' % (
                       self.__class__.__name__,
                       PROTOCOL_TYPES.get(self.protocol_header.get('protocol_id')),
                       EMI1_PRIMITIVES.get(self.body.get('message_code')),
                       DEVICE_SERVICE_IDENTIFIERS.get(self.protocol_header.get('emi_id')),
                       hex(self.body.get('message_code')))

    @staticmethod
    def _unpack_stream(fmt, stream):
        try:
            buf = stream.read(struct.calcsize(fmt))
            return struct.unpack(fmt, buf)[0]
        except struct.error as e:
            LOGGER.exception(e)

    def _pack_report_and_protocol_header(self):
        # report header
        header = bytearray(struct.pack('!B', self.report_header.get('report_id')))
        header.extend(struct.pack('!B', self.report_header.get('package_info')))
        header.extend(struct.pack('!B', self.report_header.get('data_length')))
        # protocol header
        header.extend(struct.pack('!B', self.protocol_header.get('protocol_version')))
        header.extend(struct.pack('!B', self.protocol_header.get('header_length')))
        header.extend(struct.pack('!H', self.protocol_header.get('body_length')))
        header.extend(struct.pack('!B', self.protocol_header.get('protocol_id')))
        header.extend(struct.pack('!B', self.protocol_header.get('emi_id')))
        header.extend(struct.pack('!H', self.protocol_header.get('manufacturer_code')))
        return header

    def _unpack_report_and_protocol_header(self, data):
        # report header
        self.report_header['report_id'] = self._unpack_stream('!B', data)
        self.report_header['package_info'] = self._unpack_stream('!B', data)
        self.report_header['data_length'] = self._unpack_stream('!B', data)
        # protocol header
        self.protocol_header['protocol_version'] = self._unpack_stream('!B', data)
        self.protocol_header['header_length'] = self._unpack_stream('!B', data)
        self.protocol_header['body_length'] = self._unpack_stream('!H', data)
        self.protocol_header['protocol_id'] = self._unpack_stream('!B', data)
        self.protocol_header['emi_id'] = self._unpack_stream('!B', data)
        self.protocol_header['manufacturer_code'] = self._unpack_stream('!H', data)

    def _pack_report_body(self):
        body = bytearray(struct.pack('!B', self.body.get('message_code')))
        if self.body.get('data'):
            body.extend(self.body.get('data'))
        elif self.body.get('frame'):
            #body.extend(self.body['frame'].frame)
            frame = self.body.get('frame')
            if isinstance(frame, DataRequest):
                frame = frame.pack()
            #body.extend(self.body.get('frame'))
            body.extend(frame)
        return body

    def _unpack_report_body(self, data):
        self.body['message_code'] = self._unpack_stream('!B', data)
        if self.protocol_header.get('protocol_id') == 0x0f:
            self.body['data'] = self._unpack_stream('{}s'.format(
                self.protocol_header.get('body_length') - 1), data)
            return
        self.body['frame'] = DataRequest(message=data)

    def _pad_report(self, report=None):
        _report = report or self._report
        _report.extend([0] * (64 - len(_report)))
        if report:
            return _report
        else:
            self._report = _report

    def _update_headers(self):
        if self.body.get('frame'):
            frame = self.body.get('frame')
            if isinstance(frame, DataRequest):
                frame = frame.pack()
            data = frame
            data_len = len(data)
        elif self.body.get('data'):
            data = self.body.get('data')
            data_len = len(data)
        else:
            data_len = 0
        #self.protocol_header['body_length'] = 1 + len(data) # message code + len(data)
        #self.protocol_header['body_length'] = data_len + 1 # message code + len(data)
        self.protocol_header['body_length'] = 1 + data_len  # message code + len(data)
        self.report_header['data_length'] = self.protocol_header['body_length'] + \
                                              self.protocol_header['header_length']

    def get_supported_emi_types_report(self):
        self.report_header['data_length'] = 0x09
        self.protocol_header['header_length'] = 0x08
        self.protocol_header['body_length'] = 0x01
        self.body['message_code'] = 0x01
        self._report = bytearray(self._pack_report_and_protocol_header())
        self._report.extend(self._pack_report_body())
        self._pad_report()
        return self._report

    def set_emi_type_report(self, emi_type=1):
        self.report_header['data_length'] = 0x09
        self.protocol_header['header_length'] = 0x08
        self.protocol_header['body_length'] = 0x01
        self.body['message_code'] = 0x01
        self.protocol_header['emi_id'] = emi_type
        self._report = bytearray(self._pack_report_and_protocol_header())
        self._report.extend(self._pack_report_body())
        self._pad_report()
        return self._report

    def get_bus_connection_status(self):
        self.report_header['data_length'] = 0x09
        self.protocol_header['header_length'] = 0x08
        self.protocol_header['body_length'] = 0x01
        self.body['message_code'] = 0x03
        self._report = bytearray(self._pack_report_and_protocol_header())
        self._report.extend(self._pack_report_body())
        self._pad_report()
        return self._report

    @property
    def report(self):
        self._update_headers()
        self._report = bytearray(self._pack_report_and_protocol_header())
        self._report.extend(self._pack_report_body())
        self._pad_report()
        return self._report

    @report.setter
    def report(self, data):
        data = io.BytesIO(data)
        self._unpack_report_and_protocol_header(data)
        self._unpack_report_body(data)
