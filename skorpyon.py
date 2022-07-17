#!/usr/bin/python3
"""Skorpyon: The main class of the Skorpyon program."""
import sys
from datetime import datetime
from ip_scanner import Scanner


def do_scan(ip_address, min_port, max_port):
    """Launch an AI-powered scan and print pretty output."""

    # Print a nice banner with information on which host we are about to scan
    print("_" * 60)
    print("Please wait, scanning address", ip_address)
    print("_" * 60)

    # Check the date and time the scan was started
    start_time = datetime.now()

    # TODO: Call Controller

    # Checking time again
    end_time = datetime.now()

    # Calculate the difference in time to now how long the scan took
    total_time = end_time - start_time

    # Printing the information on the screen
    print("Scanning completed in ", total_time)


if __name__ == '__main__':
    # Usage:
    # ./skorpyon <subnet>: Prints the hosts available on the local network.
    # ./skorpyon <local IP address> <min port> <max port>: Conducts a port
    # scan against a local host from <min port> to <max port>.


    if len(sys.argv) == 2:
        subnet = sys.argv[1]
        hosts = Scanner.get_hosts(subnet)
        if len(hosts) == 0:
            print("Found no hosts.")

    elif len(sys.argv) == 4:
        address = sys.argv[1]
        startPort = int(sys.argv[2])
        endPort = int(sys.argv[3])
        # TODO: Validate that address is reachable
        # validateAddress()
        if startPort < 0:
            print('Invalid start port')
        elif endPort > 65535:
            print('End port cannot exceed 65535!')
        else:
            do_scan(address, startPort, endPort)

    else:
        print('Scan IP address: ./skorpyon.py <IP address> <start port> <end port>')
        print('Example: ./skorpyon.py 192.168.0.3 1 65535\n')
        print('Get other hosts on subnet: ./skorpyon.py <subnet address>')
        print('Example: ./skorpyon.py 192.168.0.1/24\n')
