# KNXmap

A tool for scanning and auditing KNXnet/IP gateways on IP driven networks. In addition to search and identify gateways KNXmap allows to scan for devices on the KNX bus via KNXnet/IP gateways.

## Compatibility

KNXmap is based on the [asyncio](https://docs.python.org/3/library/asyncio.html) module which is available for Python 3.3 and newer. Users of Python 3.3 must install `asyncio` from [PyPI](https://pypi.python.org/pypi), Python 3.4 ships it in the standard library by default. Therefore KNXmap requires Python 3.3 or any newer version of Python.

## KNX

KNX is a standardized (EN 50090, ISO/IEC 14543), OSI-based network communications protocol for building automation. KNX is the successor to, and convergence of, three previous standards: the European Home Systems Protocol (EHS), BatiBUS, and the European Installation Bus (EIB or Instabus). The KNX standard is administered by the [KNX Association](https://www.knx.org/knx-en/index.php). ([Source](https://en.wikipedia.org/wiki/KNX_\(standard\)))

### KNXnet/IP

KNXnet/IP defines Ethernet as physical communication media. It basically allows administrators to manage KNX bus devices via IP driven networks.

**Note**: Unfourtunately the standard is proprietary which makes it impossible to be included in this repository.

## Usage

Install and run KNXmap:

```
python setup.py install
knxmap.py --help
```

Or just invoke the script locally:

```
chmod +x knxmap.py
./knxmap.py --help
```

## Scanning Modes

KNXmap supports three different scanning modes:

* Identifying KNX gateways via unicast discovery messages (default scan mode)
* Scan for bus devices attached to KNX gateways (with optional device fingerprinting)
* Searching KNX gateways via multicast messages (with `--search`)

### Discovery Mode

This is the default mode of KNXmap. It sends KNX description request to the supplied targets in order to chceck if they are KNXnet/IP gateways.

```
knxmap.py 192.168.1.100
```

KNXmap supports to scan multiple targets at once by supplying multiple IP addresses separated by a space. Targets can also be defined as networks in CIDR notation:

```
knxmap.py 192.168.1.100 192.168.1.110 192.168.2.0/24
```

### Bus Mode

In addition to the discovery mode, KNXmap also supports to scan for devices on the KNX bus.

```
knxmap.py --bus-targets 1.1.5 192.168.1.100
```

KNXmap also supports bus address ranges:

```
knxmap.py --bus-targets 1.0.0-1.1.255 192.168.1.100
```

The default mode is to only check if sending messages to a address returns an error or not. This helps to identify potential devices and alive targets.

#### Bus Device Fingerprinting

In addition to the default bus scanning KNXmap can also extract basic information from devices for further identification by supplying the `--bus-info` argument:

```
knxmap.py --bus-targets 1.1.5 --bus-info 192.168.1.100
```

### Search Mode

KNX supports finding devices by sending multicast packets that should be answered by any KNXnet/IP gateway. KNXmap supports gateway searching via the `--search` flag. It requires the `-i`/`--interface` and superuser privileges:

```
sudo knxmap.py --search --interface eth1
```

**Note**: Packet filtering rules might block the response packets. If there are no KNXnet/IP gateways answering their packets might be dropped by netfilter/iptables rules.

## Monitoring Modes

KNXmap supports two different monitoring modes:

* Bus monitoring (`--bus-monitor`) prints the raw messages received from the KNX bus.
* Group monitoring (`--group-monitor`) prints all group messages received from the KNX bus.

These monitoring modes can be useful for debugging communication on the bus. Additionally, they can be used for passive information gathering which allows to identify bus devices without sending messages to any individual or group address. Especially motion sensors or other devices that frequently send messages to the bus can easily be identified via bus monitoring.

## Hacking

Enable full debugging and verbosity for development:

```
PYTHONASYNCIODEBUG=1 knxmap.py 192.168.178.20 --bus-targets 1.1.0-1.1.6 --bus-info -v
```
