from scapy.all import *

iphdr = IP(dst='1.2.3.4')
icmphdr = ICMP()
ans = sr1(iphdr/icmphdr, filter='icmp') 
if ans:
    ans.show()
