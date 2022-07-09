"""Scanner: A Module that contains classes for port scans and other network scans."""

from scapy.all import *
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
    def connect_scan(address, min_port, max_port, timeout=0.01):

        # We will return a list of ports
        ports = []

        # Set socket timeout
        socket.setdefaulttimeout(timeout)

        # Using the range function to specify ports
        # Also we will do error handling

        try:
            for port in range(int(min_port), int(max_port)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((address, port))
                if result == 0:
                    print("Port {}:        Open".format(port))
                    ports.append(port)
                sock.close()

        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()

        except socket.gaierror:
            print("Hostname could not be resolved. Exiting")
            sys.exit()

        except socket.error:
            print("Couldn't connect to server")
            sys.exit()

        return ports

    @staticmethod
    def syn_scan(dst_ip, min_port, max_port, timeout=3):
        # Set up a list of ports
        ports = []
        # Scan from a random port
        src_port = RandShort()

        try:
            for dst_port in range(int(min_port), int(max_port)):
                stealth_scan_resp = sr1(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S"),
                                        timeout=timeout)
                if not str(type(stealth_scan_resp)).__contains__("NoneType"):
                    if stealth_scan_resp.haslayer(TCP):
                        if stealth_scan_resp.getlayer(TCP).flags == 0x12:
                            send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R"),
                                          timeout=timeout)
                            ports.append(dst_port)

        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()

        return ports
