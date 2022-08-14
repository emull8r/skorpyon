"""Scanner: A Module that contains classes for port scans and other network scans."""
from enum import Enum
from scapy.all import conf, sr1, sr
from scapy.volatile import RandShort
from scapy.sendrecv import srp
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import Ether, ARP

class ScanResult(Enum):
    """An Enum representing the state of a port: open, filtered, open/filtered, or closed"""
    OPEN = 1
    FILTERED = 2
    OPEN_OR_FILTERED = 3
    CLOSED = 4

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
    def syn_scan(dst_ip, dst_port, timeout=3):
        """Conduct a SYN scan against a destination IP and port."""
        # Scan from a random port
        src_port = RandShort()

        stealth_scan_resp = sr1(IP(dst=dst_ip)/
        TCP(sport=src_port,dport=dst_port,flags="S"),timeout=timeout)
        if "NoneType" in str(type(stealth_scan_resp)):
            return ScanResult.FILTERED
        elif stealth_scan_resp.haslayer(TCP):
            if stealth_scan_resp.getlayer(TCP).flags == 0x12:
                sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=timeout)
                return ScanResult.OPEN
            elif stealth_scan_resp.haslayer(ICMP):
                if int(stealth_scan_resp.getlayer(ICMP).type==3 and
                int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    return ScanResult.FILTERED

        return ScanResult.CLOSED

    @staticmethod
    def xmas_scan(dst_ip, dst_port, timeout=3):
        """Conduct an XMAS scan against a destination IP and port."""
        # Scan from a random port
        src_port = RandShort()

        xmas_scan_resp = sr1(IP(dst=dst_ip)/
        TCP(sport=src_port, dport=dst_port,flags="FPU"),timeout=timeout)
        if "NoneType" in str(type(xmas_scan_resp)):
            return ScanResult.OPEN_OR_FILTERED
        elif xmas_scan_resp.haslayer(TCP):
            if xmas_scan_resp.haslayer(ICMP):
                if int(xmas_scan_resp.getlayer(ICMP).type==3
                and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    return ScanResult.FILTERED

        return ScanResult.CLOSED

    @staticmethod
    def fin_scan(dst_ip, dst_port, timeout=3):
        """Conduct a FIN scan against a destination IP and port."""
        # Scan from a random port
        src_port = RandShort()

        fin_scan_resp = sr1(IP(dst=dst_ip)/
        TCP(sport=src_port, dport=dst_port,flags="F"), timeout=timeout)
        if "NoneType" in str(type(fin_scan_resp)):
            return ScanResult.OPEN_OR_FILTERED
        elif fin_scan_resp.haslayer(TCP):
            if fin_scan_resp.haslayer(ICMP):
                if int(fin_scan_resp.getlayer(ICMP).type==3
                    and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    return ScanResult.FILTERED

        return ScanResult.CLOSED

    @staticmethod
    def null_scan(dst_ip, dst_port, timeout=3):
        """Conduct a NULL scan against a destination IP and port."""
        # Scan from a random port
        src_port = RandShort()

        null_scan_resp = sr1(IP(dst=dst_ip)/
        TCP(sport=src_port, dport=dst_port,flags=""),timeout=timeout)
        if "NoneType" in str(type(null_scan_resp)):
            return ScanResult.OPEN_OR_FILTERED
        elif null_scan_resp.haslayer(TCP):
            if null_scan_resp.haslayer(ICMP):
                if int(null_scan_resp.getlayer(ICMP).type==3
                    and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    return ScanResult.FILTERED

        return ScanResult.CLOSED

    @staticmethod
    def window_scan(dst_ip, dst_port, timeout=3):
        """Conduct a Window scan against a destination IP and port."""
        # Scan from a random port
        src_port = RandShort()

        window_scan_resp = sr1(IP(dst=dst_ip)/
        TCP(sport=src_port, dport=dst_port,flags="A"),timeout=timeout)
        if "NoneType" not in str(type(window_scan_resp)):
            if window_scan_resp.haslayer(TCP):
                if window_scan_resp.getlayer(TCP).window > 0:
                    return ScanResult.OPEN

        return ScanResult.CLOSED

    @staticmethod
    def udp_scan(dst_ip, dst_port, timeout=3):
        """Conduct a UDP scan against a destination IP and port."""
        # Scan from a random port
        src_port = RandShort()

        udp_scan_resp = sr1(IP(dst=dst_ip)/
        UDP(sport=src_port, dport=dst_port),timeout=timeout)
        if "NoneType" in str(type(udp_scan_resp)):
            retrans = []
            for count in range(0,3):
                retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=timeout))
            for item in retrans:
                if "NoneType" not in str(type(item)):
                    return ScanResult.OPEN_OR_FILTERED
        elif udp_scan_resp.haslayer(UDP):
            return ScanResult.OPEN
        elif udp_scan_resp.haslayer(ICMP):
            if int(udp_scan_resp.getlayer(ICMP).type==3
                and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
                return ScanResult.FILTERED

        return ScanResult.CLOSED

    @staticmethod
    def scan_host(scan_type, dst_ip, dst_port, timeout=5):
        """Conduct a port scan against a destination IP and destination port.
        Keyword argments:
        scan_type -- The scan type:
            0/default: SYN scan
            1: XMAS scan
            2: FIN scan
            3: NULL scan
            4: Window scan
            5: UDP scan
        dst_ip -- The destination IP
        dst_port -- The destination port
        timeout -- The time to wait for a response to a sent packet
        """
        #TODO: Make scanning multithreaded / parallel in some way
        if scan_type == 1:
            print("XMAS scan!")
            return Scanner.xmas_scan(dst_ip, dst_port, timeout)
        if scan_type == 2:
            print("FIN scan!")
            return Scanner.fin_scan(dst_ip, dst_port, timeout)
        if scan_type == 3:
            print("NULL scan!")
            return Scanner.null_scan(dst_ip, dst_port, timeout)
        if scan_type == 4:
            print("WINDOW scan!")
            return Scanner.window_scan(dst_ip, dst_port, timeout)
        if scan_type == 5:
            print("UDP scan!")
            return Scanner.udp_scan(dst_ip, dst_port, timeout)

        print("SYN scan!")
        return Scanner.syn_scan(dst_ip, dst_port, timeout)
