# KNXmap

A tool for scanning and auditing KNXnet/IP gateways on IP driven networks. KNXnet/IP defines Ethernet as physical communication media for KNX (EN 50090, ISO/IEC 14543). KNXmap also allows to scan for devices on the KNX bus via KNXnet/IP gateways. In addition to scanning, KNXmap supports other modes to interact with KNX gateways like monitor bus messages or write arbitrary values to group addresses.

## Compatibility

KNXmap requires Python 3.3 or newer. There are no external dependencies, everything is included in the standard library.

*Note*: Users of Python 3.3 need to install the [asyncio](https://docs.python.org/3/library/asyncio.html) module from [PyPI](https://pypi.python.org/pypi).

## Usage

Invoke `knxmap.py` locally or install it:

```
python setup.py install
```

## Documentation

The documentation is available in the [repository wiki](https://github.com/ernw/knxmap/wiki).

## Hacking

Enable full debugging and verbosity for development:

```
PYTHONASYNCIODEBUG=1 knxmap.py -v scan 192.168.178.20 1.1.0-1.1.6 --bus-info
```
