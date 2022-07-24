"""Scanner: A Module that contains classes for port scans and other network scans."""
from scapy.all import conf, sr1, sr
from scapy.volatile import RandShort
from scapy.sendrecv import srp
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import Ether, ARP

class ScanResult:
    """Contains lists of ports that are either open, filtered,
    or open or filtered but inconclusive"""

    def __init__(self, open_ports, filtered_ports, open_or_filtered_ports):
        self.open_ports = open_ports
        self.filtered_ports = filtered_ports
        self.open_or_filtered_ports = open_or_filtered_ports

    def get_open_ports(self):
        """Get a list of ports that are definitely open."""
        return self.open_ports

    def get_filtered_ports(self):
        """Get a list of ports that are definitely filtered."""
        return self.filtered_ports

    def get_open_or_filtered_ports(self):
        """Get a list of ports that are either open or filtered.
            NOTE: These ports are distinct from the ones in the other list of ports.
        """
        return self.open_or_filtered_ports


class Scanner:
    """ A class specifically for scanning to get information about other hosts on the network.
    
    Special thanks to Interference Researcher at Infosec Institute for providing examples of
    using Scapy to conduct various types of port scans:
    https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/
    """

    last_port = 65535

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
        # Initialize lists of ports
        open_ports = []
        filtered_ports = []
        # Scan from a random port
        src_port = RandShort()

        for dst_port in range(int(min_port), int(max_port)):
            stealth_scan_resp = sr1(IP(dst=dst_ip)/
            TCP(sport=src_port,dport=dst_port,flags="S"),timeout=timeout)
            if str(type(stealth_scan_resp)).__contains__("NoneType"):
                filtered_ports.append(dst_port)
            elif stealth_scan_resp.haslayer(TCP):
                if stealth_scan_resp.getlayer(TCP).flags == 0x12:
                    sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=timeout)
                    open_ports.append(dst_port)
                elif stealth_scan_resp.haslayer(ICMP):
                    if int(stealth_scan_resp.getlayer(ICMP).type==3 and
                    int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        filtered_ports.append(dst_port)

        return ScanResult(open_ports, filtered_ports, [])

    @staticmethod
    def xmas_scan(dst_ip, min_port, max_port, timeout=3):
        """Conduct an XMAS scan against a destination IP from ports min_port to max_port."""
        filtered_ports = []
        open_or_filtered_ports = []
        # Scan from a random port
        src_port = RandShort()

        for dst_port in range(int(min_port), int(max_port)):
            xmas_scan_resp = sr1(IP(dst=dst_ip)/
            TCP(sport=src_port, dport=dst_port,flags="FPU"),timeout=timeout)
            if str(type(xmas_scan_resp)).__contains__("NoneType"):
                open_or_filtered_ports.append(dst_port)
            elif xmas_scan_resp.haslayer(TCP):
                if xmas_scan_resp.haslayer(ICMP):
                    if int(xmas_scan_resp.getlayer(ICMP).type==3
                    and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        filtered_ports.append(dst_port)

        return ScanResult([], filtered_ports, open_or_filtered_ports)

    @staticmethod
    def fin_scan(dst_ip, min_port, max_port, timeout=3):
        """Conduct a FIN scan against a destination IP from ports min_port to max_port."""
        filtered_ports = []
        open_or_filtered_ports = []
        # Scan from a random port
        src_port = RandShort()

        for dst_port in range(int(min_port), int(max_port)):
            fin_scan_resp = sr1(IP(dst=dst_ip)/
            TCP(sport=src_port, dport=dst_port,flags="F"), timeout=timeout)
            if str(type(fin_scan_resp)).__contains__("NoneType"):
                open_or_filtered_ports.append(dst_port)
            elif fin_scan_resp.haslayer(TCP):
                if fin_scan_resp.haslayer(ICMP):
                    if int(fin_scan_resp.getlayer(ICMP).type==3
                        and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        filtered_ports.append(dst_port)

        return ScanResult([], filtered_ports, open_or_filtered_ports)
    
    @staticmethod
    def null_scan(dst_ip, min_port, max_port, timeout=3):
        """Conduct a NULL scan against a destination IP from ports min_port to max_port."""
        open_or_filtered_ports = []
        filtered_ports = []
        # Scan from a random port
        src_port = RandShort()

        for dst_port in range(int(min_port), int(max_port)):
            null_scan_resp = sr1(IP(dst=dst_ip)/
            TCP(sport=src_port, dport=dst_port,flags=""),timeout=timeout)
            if str(type(null_scan_resp)).__contains__("NoneType"):
                open_or_filtered_ports.append(dst_port)
            elif null_scan_resp.haslayer(TCP):
                if null_scan_resp.haslayer(ICMP):
                    if int(null_scan_resp.getlayer(ICMP).type==3
                        and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        filtered_ports.append(dst_port)

        return ScanResult([], filtered_ports, open_or_filtered_ports)

    @staticmethod
    def window_scan(dst_ip, min_port, max_port, timeout=3):
        """Conduct a Window scan against a destination IP from ports min_port to max_port."""
        open_ports = []
        # Scan from a random port
        src_port = RandShort()

        for dst_port in range(int(min_port), int(max_port)):
            window_scan_resp = sr1(IP(dst=dst_ip)/
            TCP(sport=src_port, dport=dst_port,flags="A"),timeout=timeout)
            if window_scan_resp.haslayer(TCP):
                if window_scan_resp.getlayer(TCP).window > 0:
                    open_ports.append(dst_port)

        return ScanResult(open_ports, [], [])

    @staticmethod
    def udp_scan(dst_ip, min_port, max_port, timeout=3):
        """Conduct a UDP scan against a destination IP from ports min_port to max_port."""
        open_ports = []
        filtered_ports = []
        open_or_filtered_ports = []
        # Scan from a random port
        src_port = RandShort()

        for dst_port in range(int(min_port), int(max_port)):
            udp_scan_resp = sr1(IP(dst=dst_ip)/
            UDP(sport=src_port, dport=dst_port),timeout=timeout)
            if str(type(udp_scan_resp)).__contains__("NoneType"):
                retrans = []
                for count in range(0,3):
                    retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=timeout))
                for item in retrans:
                    if not str(type(item)).__contains__("NoneType"):
                        open_or_filtered_ports.append(dst_port)
                    elif udp_scan_resp.haslayer(UDP):
                        open_ports.append(dst_port)
                    elif udp_scan_resp.haslayer(ICMP):
                        if int(udp_scan_resp.getlayer(ICMP).type==3
                            and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
                            filtered_ports.append(dst_port)

        return ScanResult(open_ports, filtered_ports, open_or_filtered_ports)

    @staticmethod
    def scan_host(scan_type, dst_ip, min_port, max_port, timeout=3):
        """Conduct a port scan against a destination IP from ports min_port to max_port.
        Keyword argments:
        scan_type -- The scan type:
            0/default: SYN scan
            1: XMAS scan
            2: FIN scan
            3: NULL scan
            4: Window scan
            5: UDP scan
        dst_ip -- The destination IP
        min_port -- The first port in the scan range
        max_port -- The last port in the scan range
        timeout -- The time to wait for a response to a sent packet
        """
        #TODO: Make scanning multithreaded / parallel in some way
        print("Scan type: ",scan_type)
        if scan_type == 1:
            print("XMAS scan!")
            return Scanner.xmas_scan(dst_ip, min_port, max_port, timeout)
        if scan_type == 2:
            print("FIN scan!")
            return Scanner.fin_scan(dst_ip, min_port, max_port, timeout)
        if scan_type == 3:
            print("NULL scan!")
            return Scanner.null_scan(dst_ip, min_port, max_port, timeout)
        if scan_type == 4:
            print("WINDOW scan!")
            return Scanner.window_scan(dst_ip, min_port, max_port, timeout)
        if scan_type == 5:
            print("UDP scan!")
            return Scanner.udp_scan(dst_ip, min_port, max_port, timeout)

        print("SYN scan!")
        return Scanner.syn_scan(dst_ip, min_port, max_port, timeout)
