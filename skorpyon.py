#!/usr/bin/python3
"""Skorpyon: The main class of the Skorpyon program."""
import sys
from datetime import datetime
from ip_scanner import Scanner
from scan_controller import Controller


def do_scan(ip_address):
    """Launch an AI-powered scan and print pretty output."""

    # Print a nice banner with information on which host we are about to scan
    print('_' * 60)
    print('Please wait, scanning address', ip_address)
    print('_' * 60)

    # Check the date and time the scan was started
    start_time = datetime.now()

    # TODO: Call Controller
    controller = Controller()
    controller.run_scans(ip_address)

    # Checking time again
    end_time = datetime.now()

    # Calculate the difference in time to now how long the scan took
    total_time = end_time - start_time

    # Printing the information on the screen
    print('Scanning completed in ', total_time)


if __name__ == '__main__':
    # Usage:
    # ./skorpyon <subnet>: Prints the hosts available on the local network.
    # ./skorpyon <local IP address>: Conducts a port scan against a machine
    # on the local network with the specified IP address


    if len(sys.argv) == 2:
        argument = sys.argv[1]
        # If it is a subnet, it should be of the form '#.#.#.#/#'
        # Otherwise, it is an address
        if '/' in argument:
            print('Getting hosts ...')
            Scanner.get_hosts(argument)
            print('Done getting hosts.')
        else:
            do_scan(argument)
    else:
        print('Scan IP address: ./skorpyon.py <IP address>')
        print('Example: ./skorpyon.py 192.168.0.3\n')
        print('Get other hosts on subnet: ./skorpyon.py <subnet address>')
        print('Example: ./skorpyon.py 192.168.0.1/24\n')
