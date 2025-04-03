#!/usr/bin/env python3
from test import PacketBuilder
from scapy.all import *

pb = PacketBuilder()

exp = \
    pb.EAP_EXPANDED('00:37:2a', 0x01, 4) + \
    pb.Dot11TLV16(0x104a, b'\x10') + \
    pb.Dot11TLV16(0x1022, b'\x04') + \
    pb.Dot11TLV16(0x1047, b"\x38\x83\x30\x92\x30\x92\x18\x83\x9c\x77\x1c\x61\xb4\x34\xbe\xc4") + \
    pb.Dot11TLV16(0x1020, b"\x1c\x61\xb4\x34\xbe\x8e") + \
    pb.Dot11TLV16(0x101a, b"\x25\x39\x83\x86\xcd\x55\x69\x4e\x09\xdc\x0f\x7b\x05\x8e\x65\xdf")

eap = pb.EAP(code=1, id=65, type=254, data=exp)

packet = \
    pb.RadioTap() + \
    pb.Dot11(0x88, '9a:38:a4:26:aa:d6', 'c4:6e:1f:88:f6:31','9a:38:a4:26:aa:d6', fcflags=[], frag=0, seq=0, QoSControl=0x0600) + \
    pb.LLC_SNAP('00:00:00', 0b00000011, 0x888e) + \
    pb.EAPOL(version=1, type=0, length=len(eap)) + \
    eap

pkt = RadioTap(packet)
pkt.show()
wrpcap('test.pcap', raw(packet), linktype=127)

#pb.Dot11(0x80, 'ff:ff:ff:ff:ff:ff', '45:a4:d8:a5:cb:fe', '45:a4:d8:a5:cb:fe', fcflags=['From DS', '+HTC/Order'])

