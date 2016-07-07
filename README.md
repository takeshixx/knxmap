# KNXmap

A tool for scanning and auditing KNXnet/IP gateways on IP driven networks. In addition to search and identify gateways KNXmap allows to scan for devices on the KNX bus via KNXnet/IP gateways.

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

KNXmap supports to scan multiple targets at once by supplying multiple IP addresses separated by a space. Targets can also be defined as networks in CIDR notation:

```
knxmap.py 192.168.1.100 192.168.1.110 192.168.2.0/24
```

**Note**: Many KNXnet/IP gateways fail to properly handle subsequent discovery requests. As a consequence, discovering such devices can be quite unreliable!

### Bus Mode

In addition to the discovery mode, KNXmap also supports to scan for devices on the KNX bus.

```
knxmap.py --bus-targets 1.0.0-1.1.255 192.168.1.100
```

**Note**: Currently only target ranges are allowed, so at least two devices must be scanned because e.g. 1.1.1-1.1.1 is not a valid target definition.

The default mode is to only check if sending messages to a address returns an error or not. This helps to identify potential devices and alive targets.

#### Bus Device Information

In addition to the default bus scanning KNXmap can also extract basic information from devices for further identification by supplying the `--bus-info` argument:

```
knxmap.py --bus-targets 1.0.0-1.1.255 --bus-info 192.168.1.100
```

### Search Mode

KNX supports finding devices by sending multicast packets that should be answered by any KNXnet/IP gateway. KNXmap supports gateway searching via the `--search` flag. It requires the `-i`/`--interface` and superuser privileges:

```
sudo knxmap.py --search --interface eth1
```

**Note**: Packet filtering rules might block the response packets. If there are no KNXnet/IP gateways answering their packets might be dropped by iptables rules.

## Monitoring Modes

KNXmap supports two different monitoring modes:

* Bus monitoring (`--bus-monitor`) prints the raw messages received from the KNX bus.
* Group monitoring (`--group-monitor`) prints all group messages received from the KNX bus.

## TODO
 
- Implement KNXnet/IP Routing (bus.py)
- Implement ObjectServer (TCP and/or UDP?) (objectserver.py)

## Hacking

Enable full debugging and verbosity for development:

```
PYTHONASYNCIODEBUG=1 knxmap.py 192.168.178.20 --bus-targets 1.1.0-1.1.6 --bus-info -v
```