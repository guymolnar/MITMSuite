from urllib.parse import parse_qs, urlencode

from scapy.layers.http import HTTPRequest

from engine.modules.base import Module
from scapy import *
from scapy.all import *
from scapy.layers.all import *

class ProxyModule(Module):
    def __init__(self):
        self.rules = []

    def add_rule(self, host , path, replace):
        self.rules.append(
            {
                "host" : host,
                "path" : path,
                "replace" : {k : v for k, v in replace.items()}
            }
        )

    def process(self, packet):
        if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Method == b"POST" and packet.haslayer(Raw):
            for rule in self.rules:
                if packet[HTTPRequest].Host.decode() == rule["host"] and packet[HTTPRequest].Path.decode() == rule["path"]:
                    body = packet[Raw].load.decode()
                    params = parse_qs(body)
                    print(f"params: {params}")
                    for key, value in rule["replace"].items():
                        k = key
                        if k in params:
                            params[k] = [value]

                    new_body = urlencode(params, doseq=True).encode()
                    packet[Raw].load = new_body

                    del packet[IP].len
                    del packet[IP].chksum
                    del packet[TCP].chksum

                    if hasattr(packet[HTTPRequest], "Content_Length"):
                        packet[HTTPRequest].Content_Length = str(len(new_body)).encode()

                    print("Modified request.")
        return packet
