import codecs
import logging

from knxmap.messages import KnxMessage
from knxmap.usb.core import KnxHidReport

LOGGER = logging.getLogger(__name__)
TRACE_LOG_LEVEL = 9


def simple_hexdump(data):
    """Simple hexdump function if no proper module is available."""
    data = codecs.encode(data, 'hex')
    hex = ''
    for i in [data[i:i + 16] for i in range(0, len(data), 16)]:
        for j in [i[j:j + 2] for j in range(0, len(i), 2)]:
            hex += '0x%s ' % j.decode().upper()
        hex += '\n'
    return hex


try:
    from helperlib.binary import hexdump as helperlib_hexdump
    def hexdump(data):
        return '\n'.join(helperlib_hexdump(data)) + '\n'
except ImportError:
    try:
        from hexdump import hexdump as hexdump_hexdump
        def hexdump(data):
            return hexdump_hexdump(data, result='return') + '\n'
    except ImportError:
        hexdump = simple_hexdump


def trace_incoming(self, message, direction='IN'):
    return trace_packet(self, message, direction=direction)


def trace_outgoing(self, message, direction='OUT'):
    return trace_packet(self, message, direction=direction)


def trace_packet(self, message, *args, **kwargs):
    """A simple packet tracing function that will print
    information about packets."""
    if LOGGER.isEnabledFor(TRACE_LOG_LEVEL):
        output = '[PACKET TRACE]'
        direction = kwargs.get('direction', None)
        if direction and direction in ['IN', 1]:
            direction = '<<<<<<<<<< [INCOMING] <<<<<<<<<<'
        elif direction and direction in ['OUT', 0]:
            direction = '>>>>>>>>>> [OUTGOING] >>>>>>>>>>'
        else:
            direction = ''
        if isinstance(message, KnxMessage):
            output += ' ' + str(message)
            message = message.message
        elif isinstance(message, KnxHidReport):
            output += ' ' + str(message)
            message = message.report
        output += '\n' + direction + '\n'
        output += hexdump(message)
        output += direction
        LOGGER._log(TRACE_LOG_LEVEL, output, args)


def setup_logger(level):
    levels = [logging.ERROR, logging.WARN, logging.INFO, logging.DEBUG, TRACE_LOG_LEVEL]
    log_format = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s' if level > 2 else '%(message)s'
    logging.addLevelName(TRACE_LOG_LEVEL, 'TRACE')
    logging.Logger.trace = trace_packet
    logging.Logger.trace_incoming = trace_incoming
    logging.Logger.trace_outgoing = trace_outgoing
    logging.basicConfig(level=levels[min(level, len(levels) - 1)], format=log_format)
