# KNXmap

A tool for scanning and auditing KNXnet/IP gateways on IP driven networks. KNXnet/IP defines Ethernet as physical communication media for KNX (EN 50090, ISO/IEC 14543). KNXmap also allows to scan for devices on the KNX bus via KNXnet/IP gateways. In addition to scanning, KNXmap supports other modes to interact with KNX gateways like monitor bus messages or write arbitrary values to group addresses.

## Compatibility

KNXmap heavily relies on the [asyncio](https://docs.python.org/3/library/asyncio.html) module and therefore requires Python 3.4 or newer. There are just a few optional dependencies that are required for some special features.

## Usage

```
sudo python setup.py install
knxmap -h
```

## Documentation

The documentation is available in the [repository wiki](https://github.com/ernw/knxmap/wiki).

## Hacking

Enable full debugging and verbosity for development:

```
PYTHONASYNCIODEBUG=1 knxmap -v scan 192.168.178.20 1.1.0-1.1.6 --bus-info
```
