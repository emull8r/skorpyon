# skorpyon
A Python port scanner that uses Deep Q-Learning to calibrate the type of scan (SYN, XMAS, FIN, NULL, Window, UDP) against a target.

# Usage
./skorpyon (subnet): Prints the hosts available on the local network.

Example: ./skorpyon 192.168.0.1/24

./skorpyon (local IP address): Conducts a port scan against a machine  on the local network with the specified IP address.

Example: ./skorpyon 192.168.0.3

# Disclaimer
The developer is not reponsible for how end users use this program. Please use this program for education and/or legitimate white-hat penetration testing.

# Credits

Special thanks to Interference Researcher at Infosec Institute for providing examples of using Scapy to conduct various types of port scans: https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/


