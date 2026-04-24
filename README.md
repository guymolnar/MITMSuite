![MITMSuite Banner](assets/banner.png)

# MITMSuite

A Python toolkit for understanding man-in-the-middle attacks — by building one.

---

## Overview

MITMSuite implements the full MITM flow end-to-end:

- ARP poisoning  
- Transparent packet forwarding  
- Real-time traffic manipulation  

The goal:

> see what actually happens on the wire

---

## Core Model

```
Learn → Lie → Relay
```

- **Learn** — discover devices and ARP mappings  
- **Lie** — poison ARP tables using forged replies  
- **Relay** — intercept, mutate, and forward packets  

---

## Architecture

```
[ CLI ] → [ Engine ]
              ├── ARP Spoofer
              ├── Forwarder
              └── Modules Pipeline
                      ├── DNS
                      ├── Proxy
                      └── Logger
```

Each packet:

```
sniff → process → forward
```

---

## Requirements

- Python 3.x  
- Scapy  
- Npcap (Windows) / libpcap (Linux)  
- Administrator / root privileges  

---

## Installation

```bash
git clone https://github.com/yourusername/MITMSuite.git
cd MITMSuite
pip install scapy
```

---

## Usage

```bash
sudo python main.py
```

---

## Commands

| Command | Description |
|--------|------------|
| `scan` | Scan the network for devices |
| `add_target <index>` | Set a target by index |
| `targets` | Show current targets |
| `add_module <name>` | Load a module (`dns`, `proxy`, `logger`) |
| `dns_add <domain> <ip>` | Add a DNS spoof rule |
| `spoof` | Start ARP spoofing |
| `stop` | Stop spoofing and restore ARP tables |

---

## Demo

![MITMSuite Demo](assets/example.png)

---

## Modules

- **logger** — logs intercepted packets to a file  
- **dns** — spoofs DNS responses (race-based)  
- **proxy** — modifies HTTP POST data in transit  

---

## Limitations

- HTTPS prevents content rewriting  
- ARP inspection defeats spoofing  
- DNS spoofing depends on timing  
- Noisy on monitored networks  

---

## Stack

- Python  
- Scapy  
- CLI  

---

## Takeaway

Most network protocols assume:

> whoever answers is telling the truth

MITMSuite shows what happens when that assumption breaks.
