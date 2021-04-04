'''
***********************************************
Task 1.1 - sniffing packets (icmp or tcp)
Eyal Levi, Dan Davidov
***********************************************
'''

#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

print("Sniffing packets.....")
# pkt = sniff(iface=['br-a7b19a894212','enp0s3' ], filter='icmp' , prn=print_pkt)
# pkt = sniff(iface=['br-a7b19a894212','enp0s3' ], filter='host 10.9.0.5 and tcp port 23' , prn=print_pkt)
pkt = sniff(iface=['br-a7b19a894212','enp0s3' ], filter='net 8.8.0.0/16 ' , prn=print_pkt)
