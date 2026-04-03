from scapy.all import *
from scapy.layers.l2 import *

class Forwarder:
    def __init__(self, targets, gateway_ip, gateway_mac, my_mac, modules):
        self.targets = targets
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.my_mac = my_mac
        self.modules = modules
        self.sniffer = None

    def _process(self, packet):
        if not packet.haslayer(Ether):
            return

        pkt = None

        for target in self.targets.copy():
            if packet[Ether].src == target["mac"]:
                pkt = packet.copy()
                pkt[Ether].src = self.my_mac
                pkt[Ether].dst = self.gateway_mac
                break
            elif packet[Ether].src == self.gateway_mac and packet.haslayer(IP) and packet[IP].dst == target["ip"]:
                pkt = packet.copy()
                pkt[Ether].src = self.my_mac
                pkt[Ether].dst = target["mac"]
                break

        if pkt is None:
            return

        if pkt.haslayer(IP):
            del pkt[IP].chksum
        if pkt.haslayer(TCP):
            del pkt[TCP].chksum
        if pkt.haslayer(UDP):
            del pkt[UDP].chksum

        for module in self.modules:
            pkt = module.process(pkt)
            if pkt is None:
                return

        sendp(pkt, verbose=False)

    def start(self, filter_str):
        self.sniffer = AsyncSniffer(filter=filter_str, prn=self._process, store=0)
        self.sniffer.start()

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()
