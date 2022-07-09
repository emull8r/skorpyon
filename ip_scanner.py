"""Scanner: A Module that contains classes for port scans and other network scans."""

import socket
import sys
from datetime import datetime
from scapy.all import Ether, ARP, srp, conf

class Scanner:
    """ A class specifically for scanning to get information about other hosts on the network."""

    def get_hosts(self, subnet):
        """ Get the IP addresses of hosts on the subnet. """
        hosts = []
        conf.verb = 0
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2)

        for rcv in ans:
            host = rcv.sprintf(r"%ARP.psrc%")
            print(host)
            hosts.append(host)

        return hosts


    def scan_host(self, address, min_port, max_port):
        #Print a nice banner with information on which host we are about to scan
        print ("_" * 60)
        print ("Please wait, scanning remote host", address)
        print ("_" *60)

        #Check the date and time the scan was started
        t1 = datetime.now()

        #We will return a list of ports
        ports = []

        #Set socket timeout
        socket.setdefaulttimeout(0.01)

        #Using the range function to specify ports
        #Also we will do error handling

        try:
            for port in range (int(min_port),int(max_port)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((address, port))
                if result == 0:
                    print ("Port {}:        Open".format(port))
                    ports.append(port)
                sock.close()

        except KeyboardInterrupt:
            print ("You pressed Ctrl+C")
            sys.exit()

        except socket.gaierror:
            print ("Hostname could not be resolved. Exiting")
            sys.exit()

        except socket.error:
            print ("Couldn't connect to server")
            sys.exit()

        #Checking time again
        t2 = datetime.now()

        #Calculate the difference in time to now how long the scan took
        total = t2 - t1

        #Printing the information on the screen
        print ("Scanning Completed in in ", total)

        return ports

