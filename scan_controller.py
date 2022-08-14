"""Scan Controller: Contains the controller of the AI scanner."""
from ip_scanner import ScanResult, Scanner
from scanner_ai import Brain

OPEN_PORT_SCORE = 1 # Score for the reward of finding open ports
FILTERED_PORT_SCORE = 0.5 # Score for the reward of finding filtered ports
OPEN_OR_FILTERED_SCORE = 0.25 # Score for inconclusively filtered or open ports
MAX_PORT = 65535 # The maximum port
N_SCAN_TYPES = 6 # The number of scan types

class Controller:
    """Controls the AI / smart scanning.

        Scan types: SYN, XMAS, FIN, NULL, ACK, Window, and UDP = 7 actions
        Ports: 0 - 65535 = 65536 ports

        Input: The range of ports to scan.

        Output: 1 of 7 scan types to use against the range.

        Finding a filtered port should give half the reward of finding an open port.
    """

    def __init__(self):
        # Initialize the brain
        self.brain = Brain(input_size=(MAX_PORT+1), output_size=N_SCAN_TYPES)
        # Load the last model, if it exists
        self.brain.load()
        self.scores = []
        self.last_scan_type = 0
        self.last_min_port = 20
        self.last_max_port = 40
        self.last_timeout = 5
        self.last_reward = 0
        self.all_open_ports = set()
        self.all_filtered_ports = set()
        self.all_open_or_filtered_ports = set()

    def int_to_state(self, min_value, max_value, actual_value):
        """Convert an int to an array of zeroes of size N+1, where N
        is max_value, and set the index [actual_value] to 1"""
        if min_value <= actual_value and actual_value <= max_value:
            array = [0] * (max_value+1)
            array[actual_value] = 1
            return array
        else:
            return []

    def scan_host(self, target_ip, port, specific_action=-1):
        """Scan a specific port against a target IP address.
        We can use a specific scan type for the scan."""
        last_signal = self.int_to_state(0, MAX_PORT, port)
        action = self.brain.update(self.last_reward, last_signal, specific_action)
        self.scores.append(self.brain.score())
        self.last_scan_type = action
        result = Scanner.scan_host(self.last_scan_type, target_ip,
            port, self.last_timeout)
        # Calculate the reward based on the result
        calculated_reward = 0
        if result == ScanResult.OPEN:
            calculated_reward = OPEN_PORT_SCORE
            self.all_open_ports.add(port)
        elif result == ScanResult.FILTERED:
            calculated_reward = FILTERED_PORT_SCORE
            self.all_filtered_ports.add(port)
        elif result == ScanResult.OPEN_OR_FILTERED:
            calculated_reward = OPEN_OR_FILTERED_SCORE
            self.all_open_or_filtered_ports.add(port)
        # We are rewarded for finding open, filtered, or open/filtered ports
        if calculated_reward == 0:
            self.last_reward = -1
        else:
            self.last_reward = calculated_reward

    def run_scans(self, target_ip, start_port, end_port, try_all_scan_types=True):
        """Scan a target IP from ports [start port] to [end port].
            target_ip -- The IP of the machine to scan
            start_port -- The first port in the range of ports to scan
            end_port -- The last port in the range of ports to scan
            try_all_scan_types -- If True, try all scan types for each port,
                                rather than using them AI-chosen scan types.
                                The purpose is to expose the AI to the results
                                of different scan types.
        """
        self.last_min_port = start_port
        self.last_max_port = end_port
        for port in range(self.last_min_port, self.last_max_port):
            # If we are training, try all scan types against all ports
            if try_all_scan_types:
                for i in range(0,N_SCAN_TYPES):
                    self.scan_host(target_ip, port, i)
            # Otherwise, just scan each port
            else:
                self.scan_host(target_ip, port)
        # Save the model
        self.brain.save()
        # Print the results
        if len(self.all_open_ports) > 0:
            print('OPEN PORTS: ', self.all_open_ports)
        else:
            print('No conclusively open ports found.')
        if len(self.all_filtered_ports) > 0:
            print('FILTERED PORTS: ', self.all_filtered_ports)
        else:
            print('No conclusively filtered ports found.')
        if len(self.all_open_or_filtered_ports) > 0:
            print('INCONCLUSIVELY OPEN OR FILTERED PORTS: ', self.all_open_or_filtered_ports)
        else:
            print('No inconclusively open or filtered ports found.')
