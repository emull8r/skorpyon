#!/usr/bin/python3
"""Skorpyon: The main class of the Skorpyon program."""
import sys
from datetime import datetime
from ip_scanner import Scanner

if __name__ == '__main__':

    if len(sys.argv) < 4:
        print('Usage: ./skorpyon.py <subnet> <start port> <end port>')
        print('Example: ./skorpyon.py 192.168.0.1/24 1 65535\n')

    elif len(sys.argv) == 4:
        subnet = sys.argv[1]
        startPort = int(sys.argv[2])
        endPort = int(sys.argv[3])

        # Print a nice banner with information on which host we are about to scan
        print("_" * 60)
        print("Please wait, scanning subnet", subnet)
        print("_" * 60)

        # Check the date and time the scan was started
        t1 = datetime.now()

        hosts = Scanner.get_hosts(subnet)

        if len(hosts) == 0:
            print("Found no hosts.")

        for address in hosts:
            open_ports = Scanner.syn_scan(address, startPort, endPort)
            if len(open_ports) == 0:
                print("No open ports at "+address)
            else:
                print("Open ports of "+address+":")
                for open_port in open_ports:
                    print(open_port)

        # Checking time again
        t2 = datetime.now()

        # Calculate the difference in time to now how long the scan took
        total = t2 - t1

        # Printing the information on the screen
        print("Scanning Completed in ", total)
