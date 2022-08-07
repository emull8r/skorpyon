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
        self.brain = Brain(input_size=1, output_size=1)
        # Load the last model, if it exists
        self.brain.load()
        self.scores = []
        self.last_scan_type = 0
        self.last_min_port = 20
        self.last_max_port = 40
        self.last_timeout = 3
        self.last_reward = 0
        self.all_open_ports = set()
        self.all_filtered_ports = set()
        self.all_open_or_filtered_ports = set()

    def run_scans(self, target_ip, start_port, end_port, n_runs):
        """Scan a target IP from ports [start port] to [end port] N times."""
        self.last_min_port = start_port
        self.last_max_port = end_port
        for i in range(n_runs):
            for port in range(self.last_min_port, self.last_max_port):
                last_signal = [self.last_scan_type]
                action = self.brain.update(self.last_reward, last_signal)
                self.scores.append(self.brain.score())
                self.last_scan_type = action.item()
                result = Scanner.scan_host(self.last_scan_type, target_ip,
                port, port, self.last_timeout)
                # Add the open ports
                for port in result.open_ports:
                    self.all_open_ports.add(port)
                for port in result.filtered_ports:
                    self.all_filtered_ports.add(port)
                for port in result.open_or_filtered_ports:
                    self.all_open_or_filtered_ports.add(port)
                # Calculate scores to improve the machine learning
                open_reward = OPEN_PORT_SCORE * len(result.open_ports)
                filtered_reward = FILTERED_PORT_SCORE * len(result.filtered_ports)
                open_or_filtered_reward = OPEN_OR_FILTERED_SCORE * len(result.open_or_filtered_ports)
                calculated_reward =  open_reward + filtered_reward + open_or_filtered_reward
                self.last_reward = calculated_reward
                # if calculated_reward == 0:
                #     self.last_reward = -1
                # else:
                #     self.last_reward = calculated_reward
        # Save the model
        self.brain.save()
        # Print the results
        if len(self.all_open_ports) > 0:
            print("OPEN PORTS: ", self.all_open_ports)
        else:
            print("No conclusively open ports found.")
        if len(self.all_filtered_ports) > 0:
            print("FILTERED PORTS: ", self.all_filtered_ports)
        else:
            print("No conclusively filtered ports found.")
        if len(self.all_open_or_filtered_ports) > 0:
            print("INCONCLUSIVELY OPEN OR FILTERED PORTS: ", self.all_open_or_filtered_ports)
        else:
            print("No inconclusively open or filtered ports found.")
