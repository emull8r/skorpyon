"""Scan Controller: Contains the controller of the AI scanner."""
from ip_scanner import Scanner
from scanner_ai import Brain

OPEN_PORT_SCORE = 1
FILTERED_PORT_SCORE = 0.5
OPEN_OR_FILTERED_SCORE = 0.25

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
        self.brain = Brain(input_size=4, output_size=4)
        # Load the last model, if it exists
        self.brain.load()
        self.scores = []
        self.last_scan_type = 0
        self.last_min_port = 0
        self.last_max_port = 1000
        self.last_timeout = 3
        self.last_reward = 0

    def run_scans(self, target_ip, n_runs=100):
        """Scan a target IP n times."""
        for i in range(n_runs):
            print("Run #", i)
            last_signal = [self.last_scan_type, self.last_min_port,
            self.last_max_port, self.last_timeout]
            action = self.brain.update(self.last_reward, last_signal)
            self.scores.append(self.brain.score())
            #TODO: Figure out how to convert tensors to numbers
            self.last_scan_type = action[0]
            self.last_min_port = action[1]
            self.last_max_port = action[2]
            self.last_timeout = action[3]
            result = Scanner.scan_host(self.last_scan_type, target_ip,
            self.last_min_port, self.last_max_port, self.last_timeout)
            open_reward = OPEN_PORT_SCORE * len(result.open_ports)
            filtered_reward = FILTERED_PORT_SCORE * len(result.filtered_ports)
            open_or_filtered_reward = OPEN_OR_FILTERED_SCORE * len(result.open_or_filtered_ports)
            self.last_reward =  open_reward + filtered_reward + open_or_filtered_reward
        self.brain.save()
