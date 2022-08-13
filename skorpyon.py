#!/usr/bin/python3
"""Skorpyon: The main class of the Skorpyon program."""
import sys
from datetime import datetime
from ip_scanner import Scanner
from scan_controller import Controller

def do_scan(target_ip, start_port, end_port, allscans):
    """Launch an AI-powered scan and print pretty output."""

    # Print a nice banner with information on which host we are about to scan
    print('_' * 60)
    print('Please wait, scanning address', target_ip)
    print('_' * 60)

    # Check the date and time the scan was started
    start_time = datetime.now()

    controller = Controller()

    try:
        controller.run_scans(target_ip, start_port, end_port, allscans)
    except KeyboardInterrupt:
        print("Abort")

    # Checking time again
    end_time = datetime.now()

    # Calculate the difference in time to now how long the scan took
    total_time = end_time - start_time

    # Printing the information on the screen
    print('Scanning completed in ', total_time)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        argument = sys.argv[1]
        # If it is a subnet, it should be of the form '#.#.#.#/#'
        # Otherwise, it is an address
        if '/' in argument:
            print('Getting hosts ...')
            Scanner.get_hosts(argument)
            print('Done getting hosts.')
        else:
            print('Invalid argument. Example subnet: 192.168.0.1/24')
    elif len(sys.argv) == 4:
        do_scan(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), False)
    elif len(sys.argv) == 5 and sys.argv[4] == '-allscans':
        do_scan(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), True)
    else:
        print('Get other hosts on subnet: ./skorpyon.py <subnet address>')
        print('Example: ./skorpyon.py 192.168.0.1/24\n')
        print('Scan IP address from start port to end port: '+
        './skorpyon.py <IP address> <start port> <end port>')
        print('Example: ./skorpyon.py 192.168.0.3 1 1000\n')
        print('Scan IP address from start port to end port, using all scan types for each port: '+
        './skorpyon.py <IP address> <start port> <end port> -allscans')
        print('Example: ./skorpyon.py 192.168.0.3 1 1000 -allscans\n')
