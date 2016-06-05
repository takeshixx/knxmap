import logging
import ipaddress

LOGGER = logging.getLogger(__name__)

class Targets:
    """A helper class that expands provided target definitions to a list of tuples."""
    def __init__(self, targets=set(), ports=3671):
        self.targets = set()
        self.ports = set()
        if isinstance(ports, list):
            for p in ports:
                self.ports.add(p)
        elif isinstance(ports, int):
            self.ports.add(ports)
        else:
            self.ports.add(3671)

        if isinstance(targets, set) or \
            isinstance(targets, list):
            self._parse(targets)

    def _parse(self, targets):
        """Parse all targets with ipaddress module (with CIDR notation support)."""
        for target in targets:
            try:
                _targets = ipaddress.ip_network(target, strict=False)
            except ValueError:
                LOGGER.error('Invalid target definition, ignoring it: {}'.format(target))
                continue

            if '/' in target:
                _targets = _targets.hosts()

            for _target in _targets:
                for port in self.ports:
                    self.targets.add((str(_target), port))


class KnxTargets:
    """A helper class that expands knx bus targets to lists."""
    def __init__(self, targets):
        self.targets = set()
        if not targets:
            self.targets = None
        elif not '-' in targets and self.is_valid_physical_address(targets):
            self.targets.add(targets)
        else:
            assert isinstance(targets, str)
            if '-' in targets and targets.count('-') < 2:
                # TODO: also parse dashes in octets
                try:
                    f, t = targets.split('-')
                except ValueError:
                    return
                if not self.is_valid_physical_address(f) or \
                        not self.is_valid_physical_address(t):
                    LOGGER.error('Invalid physical address')
                    # TODO: make it group address aware
                elif self.physical_address_to_int(t) <= \
                        self.physical_address_to_int(f):
                    LOGGER.error('From should be smaller then To')
                else:
                    self.targets = self.expand_targets(f, t)

    @staticmethod
    def expand_targets(f, t):
        start = list(map(int, f.split('.')))
        end = list(map(int, t.split('.')))
        temp = start
        ret = set()
        ret.add(f)
        while temp != end:
            start[2] += 1
            for i in (2, 1):
                if temp[i] == 256:
                    temp[i] = 0
                    temp[i - 1] += 1
            ret.add('.'.join(map(str, temp)))
        return ret

    @staticmethod
    def physical_address_to_int(address):
        parts = address.split('.')
        return (int(parts[0]) << 12) + (int(parts[1]) << 8) + (int(parts[2]))

    @staticmethod
    def is_valid_physical_address(address):
        assert isinstance(address, str)
        try:
            parts = [int(i) for i in address.split('.')]
        except ValueError:
            return False
        if len(parts) is not 3:
            return False
        if (parts[0] < 1 or parts[0] > 15) or (parts[1] < 0 or parts[1] > 15):
            return False
        if parts[2] < 0 or parts[2] > 255:
            return False
        return True

    @staticmethod
    def is_valid_group_address(address):
        assert isinstance(address, str)
        try:
            parts = [int(i) for i in address.split('/')]
        except ValueError:
            return False
        if len(parts) < 2 or len(parts) > 3:
            return False
        if (parts[0] < 0 or parts[0] > 15) or (parts[1] < 0 or parts[1] > 15):
            return False
        if len(parts) is 3:
            if parts[2] < 0 or parts[2] > 255:
                return False
        return True


class BusResultSet:

    def __init__(self):
        pass