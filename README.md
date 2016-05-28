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

### Discovery Mode

This is the default mode of KNXmap. It sends KNX description request to the supplied targets in order to chceck if they are KNXnet/IP gateways.

```
knxmap.py 192.168.1.100
```

KNXmap supports to scan multiple targets at once by supplying multiple IP addresses separated by a space. If the [ipaddress](https://docs.python.org/3/library/ipaddress.html) module is available, also CIDR notations in target definitions are supported:

```
knxmap.py 192.168.1.100 192.168.1.110 192.168.2.0/24
```

**Note**: The ipaddress module is available in the standard library since Python 3.3. However, they is also a port for older versions available on [PyPI](https://pypi.python.org/pypi/ipaddress).

### Bus Mode

In addition to the discovery mode, KNXmap also supports to scan for devices on the KNX bus.

```
knxmap.py --bus 192.168.1.100
```

### Search Mode

KNX supports finding devices by sending multicast packets that should be answered by any KNXnet/IP gateway. KNXmap supports gateway searching via the --search flag. It requires the -i/--interface and superuser privileges:

```
sudo knxmap.py --search --interface eth1
```

**Note**: Packet filtering rules might block the response packets. If there are no KNXnet/IP gateways answering their packets might be dropped by iptables rules.

## Monitoring Modes

KNXmap supports two different monitoring modes:

* Bus monitoring (--bus-monitor) prints the raw messages received from the KNX bus.
* Group monitoring (--group-monitor) prints all group messages received from the KNX bus.

## TODO (will be removed from the readme)

- More information about vendor ID's and the area where they are located in the memory
- Add the device databases from the vendor sites
- Implement ObjectServer (TCP and/or UDP?)