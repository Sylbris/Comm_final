'''
***********************************************
Task 1.3 - Traceroute
Eyal Levi, Dan Davidov
***********************************************
'''

from scapy.all import *

host = '8.8.8.8'
print("Traceroute:", host)
ttl=1
while ttl<=100:
    a = IP(dst=host, ttl=ttl)
    b = ICMP()
    reply = sr1(a/b, timeout=5, verbose=0)

    if reply is None:
        print (ttl, '*')
    elif reply.type == 0:
        print (ttl, reply.src)
        break
    else:
        print (ttl, reply.src)
    ttl += 1