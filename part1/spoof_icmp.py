'''
***********************************************
Task 1.2 - icmp spoofing
Eyal Levi, Dan Davidov
***********************************************
'''

from scapy.all import *

iphdr = IP(src='1.2.3.4', dst='10.9.0.5')
icmphdr = ICMP()
ans = sr1(iphdr/icmphdr, filter='icmp') 
if ans:
    ans.show()