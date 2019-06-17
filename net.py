import os
import netifaces as ni


class Net:
    def __init__(self):
        self.attacker_ip = ""
        self.victim_ip = ""
        self.interface = ""
        self.gateway = ""
        self.forward_enabled = False

    def enable_forward(self):
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        self.forward_enabled = True

    def disable_forward(self):
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        self.forward_enabled = False

    def get_avail_interfaces(self):
        interfaces = ni.interfaces()
        return interfaces

    def set_interface(self, interface):
        self.interface = interface

    def set_victim_ip(self, victim_ip):
        self.victim_ip = victim_ip

    def get_interface(self):
        return self.interface

    def get_attacker_ip(self):
        ip = ni.ifaddresses(self.interface)[ni.AF_INET][0]['addr']
        return ip

    def get_victim_ip(self):
        return self.victim_ip

    def get_gateway_ip(self):
        gwd = ni.gateways()
        return list(gwd['default'].values())[0][0]

    def get_net_mask(self):
        net_mask = ni.ifaddresses(self.interface)[ni.AF_INET][0]['netmask']
        return net_mask
