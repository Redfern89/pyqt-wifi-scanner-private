#!/usr/bin/env python3

from scapy.all import *
import pcapy

pcap = pcapy.open_live('radio0mon', 65535, 0, 0)

def rnd_bssid():
	return ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(6))

#pkt = \
#    RadioTap() / \
#    Dot11(type=0, subtype=6, addr1=rnd_bssid(), addr2=rnd_bssid(), addr3=rnd_bssid()) / \
#	Dot11Action(category=0, action=0)
    #Dot11ReassoResp(cap=0x1101, status=0, AID=1) / \
	#Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96')

llc = LLC() / SNAP(OUI=0, code=0x888E) 

print(llc.show())

#while 1:
#	pcap.sendpacket(raw(pkt))