# KNXmap

A tool for scanning and auditing KNXnet/IP gateways on IP driven networks. KNXnet/IP defines Ethernet as physical communication media for KNX (EN 50090, ISO/IEC 14543). KNXmap also allows to scan for devices on the KNX bus via KNXnet/IP gateways. In addition to scanning, KNXmap supports other modes to interact with KNX gateways like monitor bus messages or write arbitrary values to group addresses.

## Compatibility

KNXmap is based on the [asyncio](https://docs.python.org/3/library/asyncio.html) module which is available for Python 3.3 and newer. Users of Python 3.3 must install `asyncio` from [PyPI](https://pypi.python.org/pypi), Python 3.4 ships it in the standard library.

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
knxmap.py scan 192.168.1.100
```

KNXmap supports to scan multiple targets at once by supplying multiple IP addresses separated by a space. Targets can also be defined as networks in CIDR notation:

```
knxmap.py scan 192.168.1.100 192.168.1.110 192.168.2.0/24
```

### Bus Mode

In addition to the discovery mode, KNXmap also supports to scan for devices on the KNX bus.

```
knxmap.py scan 192.168.1.100 1.1.5
```

KNXmap also supports bus address ranges:

```
knxmap.py scan 192.168.1.100 1.0.0-1.1.255
```

The default mode is to only check if sending messages to a address returns an error or not. This helps to identify potential devices and alive targets.

#### Bus Device Fingerprinting

In addition to the default bus scanning KNXmap can also extract basic information from devices for further identification by supplying the `--bus-info` argument:

```
knxmap.py scan 192.168.1.100 1.1.5 --bus-info
```

### Search Mode

KNX supports finding devices by sending multicast packets that should be answered by any KNXnet/IP gateway. KNXmap supports gateway searching via the `--search` flag. It requires the `-i`/`--interface` and superuser privileges:

```
sudo knxmap.py --interface eth1 search 
```

**Note**: Packet filtering rules might block the response packets. If there are no KNXnet/IP gateways answering their packets might be dropped by netfilter/iptables rules.

## Monitoring Modes

KNXmap supports two different monitoring modes:

* Bus monitoring: prints the raw messages received from the KNX bus.

```
knxmap.py monitor 192.168.1.100
```

* Group monitoring: prints all group messages received from the KNX bus.

```
knxmap.py monitor 192.168.1.100 --group-monitor
```

These monitoring modes can be useful for debugging communication on the bus. Additionally, they can be used for passive information gathering which allows to identify bus devices without sending messages to any individual or group address. Especially motion sensors or other devices that frequently send messages to the bus can easily be identified via bus monitoring.

## Group Write

KNXmap allows one to write arbitrary values to any group address on the bus. The following example writes the value `1` to the group address `0/0/1`:

```
knxmap.py write 192.168.1.100 0/0/1 1
```

## APCI Functions

KNXmap provides wrappers for several APCI functions via the `apci` command. For example sending an `A_Authorize` message:

```
knxmap.py apci 192.168.0.10 1.1.1 Authorize --key 123
```

Sending the `A_Authorize` message will return the authorization level (0 is the highest, 15 the lowest). Some more examples:

```
knxmap.py apci 192.168.0.10 1.1.1 DeviceDescriptor_Read
knxmap.py apci 192.168.0.10 1.1.1 PropertyValue_Read --property-id 0xb
knxmap.py apci 192.168.0.10 1.1.1 Memory_Read --memory-address 0x0060
```

## Hacking

Enable full debugging and verbosity for development:

```
PYTHONASYNCIODEBUG=1 knxmap.py -v scan 192.168.178.20 1.1.0-1.1.6 --bus-info
```
