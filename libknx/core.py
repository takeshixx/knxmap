# Core stuff, making connections and such
import socket
import scapy.all

from .messages import KnxSearchRequest, KnxConnectionRequest

class KnxConnection():

    def __init__(self, destination):
        self.destination = destination


    def find_knx_gateways(self):
        port = 55772
        knx_search_request = KnxSearchRequest(port=port)
        multicast_packet = scapy.all.IP(dst='224.0.23.12')/scapy.all.UDP(dport=3671)/scapy.all.Raw(load=knx_search_request.get_message())
        response = scapy.all.sr(multicast_packet, inter=5, retry=2, timeout=1)

        print response

    def _establish_knx_tunnel(self, knx_gateway):
        port = 55773
        knx_connection_request = KnxSearchRequest(port=port)
        packet = scapy.all.IP(dst=knx_gateway)/scapy.all.UDP(dport=3671)/scapy.all.Raw(load=knx_connection_request.get_message())
        response = sendp(packet)

        print response


def discover_gateways():
    pass


def identify_gateway():
    pass