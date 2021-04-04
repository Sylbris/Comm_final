'''
***********************************************
Task 1.3 - Traceroute
Eyal Levi, Dan Davidov
***********************************************
'''
from scapy.all import *

def handle_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 0:
        pkt[IP].dst = '10.9.0.1'
    if ICMP in pkt and pkt[ICMP].type == 8:
        ip = IP(dst = pkt[IP].src, src = pkt[IP].dst, ihl=pkt[IP].ihl)
        data = pkt[Raw]
        icmp = ICMP(type=0, code=0, seq=pkt[ICMP].seq, id=pkt[ICMP].id)
        print("\nSending spoofed icmp: ")
        print("\tSource: ", ip.src," Destination: ", ip.dst)
        send(ip/icmp/data)
    elif ARP in pkt and pkt[ARP].op == 1:
        arp = ARP(hwlen=6, plen=4, op=2, pdst=pkt[ARP].psrc, psrc=pkt[ARP].pdst, hwdst=pkt[ARP].hwsrc, hwsrc=pkt[ARP].hwdst)
        send(arp)

print("Sniffing packet....")
pkt = sniff(iface='br-a7b19a894212', filter='icmp or arp' , prn=handle_pkt)

# iface='br-a7b19a894212', 