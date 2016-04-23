# KNXmap

A tool that scans for KNXnet/IP gateways on the network and for attached devices on the KNX bus.

## Compatibility

KNXmap is based on the [asyncio](https://docs.python.org/3/library/asyncio.html) module which is available for Python 3.3 and newer. Users of Python 3.3 must install `asyncio` from [PyPI](https://pypi.python.org/pypi), Python 3.4 ships it in the standard library by default. Therefore KNXmap requires Python 3.3 or any newer version of Python.

## KNXnet/IP

KNXnet/IP is a standard that defines IP as a medium for [KNX](https://www.knx.org/knx-en/index.php) related communication. It basically allows administrators to administrate KNX devices via IP driven networks.

Unfourtunately the standard is properitary which makes it impossible to be included in this repository.

## Scanning Modes

KNXmap supports three different scanning modes:

* Searching KNX gateways via multicast messages (with `--search`)
* Identifying KNX gateways with discovery messages (default scan mode)
* Scan for bus devices attached to KNX gateways

## TODO (will be removed from the readme)

- More information about vendor ID's and the area where they are located in the memory
- Add the device databases from the vendor sites
- Implement busmonitor
- Implement ObjectServer (TCP and/or UDP?)