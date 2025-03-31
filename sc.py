#!/usr/bin/env python3

from scapy.all import *
from test import PacketBuilder

pb = PacketBuilder()

#e = EAPOL(type=1)
#e.show()

e = LLC() / SNAP() / EAPOL(type=0, version=1) / EAP(code=2, id=11, type=1, identity="WFA-SimpleConfig-Registrar-1-0")
e.show()

print(raw(e))
