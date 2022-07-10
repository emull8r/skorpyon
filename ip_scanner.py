"""Scanner: A Module that contains classes for port scans and other network scans."""
import sys
from scapy.all import conf, sr1, sr
from scapy.volatile import RandShort
from scapy.sendrecv import srp
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, ARP


class Scanner:
    """ A class specifically for scanning to get information about other hosts on the network."""
    scan_timeout = 2

    def __init__(self):
        self.scan_timeout = 2

    @staticmethod
    def get_hosts(subnet, timeout=2):
        """ Get the IP addresses of hosts on the subnet. """
        hosts = []
        conf.verb = 0
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=timeout)

        for snd, rcv in ans:
            host = rcv.sprintf(r"%ARP.psrc%")
            print(host)
            hosts.append(host)

        return hosts

    @staticmethod
    def syn_scan(dst_ip, min_port, max_port, timeout=3):
        """Conduct a SYN scan against a destination IP from ports min_port to max_port."""
        # Set up a list of ports
        ports = []
        # Scan from a random port
        src_port = RandShort()

        try:
            for dst_port in range(int(min_port), int(max_port)):
                stealth_scan_resp = sr1(IP(dst=dst_ip) / TCP(sport=src_port,
                dport=dst_port, flags="S"),
                                        timeout=timeout)
                if not str(type(stealth_scan_resp)).__contains__("NoneType"):
                    if stealth_scan_resp.haslayer(TCP):
                        if stealth_scan_resp.getlayer(TCP).flags == 0x12:
                            send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port,
                            dport=dst_port, flags="R"),
                                          timeout=timeout)
                            ports.append(dst_port)

        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()

        return ports
