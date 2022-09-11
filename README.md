# skorpyon
A Python port scanner that uses Deep Q-Learning to calibrate the type of scan (SYN, XMAS, FIN, NULL, Window, UDP) against a target.

# Usage
Get other hosts on subnet: ./skorpyon.py [subnet address]

Example: ./skorpyon.py 192.168.0.1/24\n

Scan IP address from start port to end port: ./skorpyon.py [IP address] [start port] [end port]

Example: ./skorpyon.py 192.168.0.3 1 1000

Scan IP address from start port to end port, using all scan types for each port: ./skorpyon.py [IP address] [start port] [end port] -allscans

Example: ./skorpyon.py 192.168.0.3 1 1000 -allscans

# Disclaimer
The developer is not reponsible for what end users do with this program.

Users should only scan networks that they own or have permission to scan for education or legitimate white-hat penetration testing.

# Credits

Special thanks to Interference Researcher at Infosec Institute for providing examples of using Scapy to conduct various types of port scans: https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/

Special thanks to Hadelin de Ponteves and Kirill Eremenko for providing a Deep Q-Learning AI template in their Udemy course: https://www.udemy.com/course/artificial-intelligence-az/


