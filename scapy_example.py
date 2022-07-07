#! /usr/bin/python
import sys

variable = "192.168.0.1/24"

from scapy.all import srp, Ether, ARP, conf
conf.verb = 0
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=variable),
                 timeout=2)

print(r"\begin{tabular}{|l|l|}")
print(r"\hline")
print(r"MAC & IP\\")
print(r"\hline")
for snd,rcv in ans:
    print(rcv.sprintf(r"%Ether.src% & %ARP.psrc%\\"))
print(r"\hline")
print(r"\end{tabular}")