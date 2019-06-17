import nmap
import os
import socket
import colors
from subnet import subnet_calc


class Discover:
    def __init__(self):
        self.hosts = []
        self.count = ""

    # Convert to CIDR notation
    def netmask_to_cidr(self, net_mask):
        return(sum([bin(int(bits)).count("1") for bits in net_mask.split(".")]))

    # Get all hosts in the network
    def discover(self, attacker_ip, net_mask):
        self.count = 0
        ip_range = str(subnet_calc(attacker_ip, net_mask)) + \
            "/" + str(self.netmask_to_cidr(net_mask))
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_range, arguments='-sP')

        for host in nm.all_hosts():
            if nm[host].hostname() != "":
                print('\t{}) {:20} {:<10}'.format(self.count, host,
                                                  colors.ORANGE + nm[host].hostname() + colors.DEFAULT))
            else:
                print('\t{}) {}'.format(self.count, host))
            self.hosts.append(host)
            self.count += 1

    # Select the victim
    def select_host(self):
        ans = ""
        while not ans.strip().isdigit() or int(ans.strip()) > self.count:
            ans = input(colors.BLUE + "\nmitm" + colors.WHITE + ":" +
                        colors.BLUE + "victim_ip" + colors.WHITE + "> " + colors.DEFAULT)
        return self.hosts[int(ans)]
