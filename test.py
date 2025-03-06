#!/usr/bin/env python3

import struct
import sys
import json
import csv
import re
import os
import time
import signal
import threading
import subprocess
import random
import contextlib

from scapy.all import *

beacon_raw = \
b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x94\x09\xa0\x00\xd7\x01" \
b"\x00\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\xec\x43\xf6\x05" \
b"\xa4\xbc\xec\x43\xf6\x05\xa4\xbc\xa0\x25\x56\x31\x76\x26\x9b\x01" \
b"\x00\x00\x64\x00\x11\x04\x00\x0a\x53\x6f\x76\x4e\x65\x74\x5f\x53" \
b"\x56\x76\x01\x08\x82\x84\x8b\x96\x12\x24\x48\x6c\x03\x01\x09\x32" \
b"\x04\x0c\x18\x30\x60\x07\x06\x52\x55\x20\x01\x0b\x14\x33\x08\x20" \
b"\x01\x02\x03\x04\x05\x06\x07\x33\x08\x21\x05\x06\x07\x08\x09\x0a" \
b"\x0b\x05\x04\x00\x01\x00\x00\xdd\x27\x00\x50\xf2\x04\x10\x4a\x00" \
b"\x01\x10\x10\x44\x00\x01\x02\x10\x47\x00\x10\xbc\x32\x9e\x00\x1d" \
b"\xd8\x11\xb2\x86\x01\xec\x43\xf6\x05\xa4\xbc\x10\x3c\x00\x01\x01" \
b"\x2a\x01\x04\x2d\x1a\xee\x11\x17\xff\xff\x00\x00\x01\x00\x00\x00" \
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x3d" \
b"\x16\x09\x07\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
b"\x00\x00\x00\x00\x00\x00\x00\xdd\x1a\x00\x50\xf2\x01\x01\x00\x00" \
b"\x50\xf2\x02\x02\x00\x00\x50\xf2\x02\x00\x50\xf2\x04\x01\x00\x00" \
b"\x50\xf2\x02\x30\x18\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac" \
b"\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\xdd\x18\x00" \
b"\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42" \
b"\x43\x5e\x00\x62\x32\x2f\x00\x0b\x05\x02\x00\x42\x12\x7a\xdd\x07" \
b"\x00\x0c\x43\x04\x00\x00\x00"

beacon_raw_1 = \
b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x0c\x9e\x09\xc0\x00\xc5\x01" \
b"\x00\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x40\x3f\x8c\x93" \
b"\x04\x90\x40\x3f\x8c\x93\x04\x90\x80\xd6\x61\xe0\x3a\xa2\xc2\x02" \
b"\x00\x00\x64\x00\x31\x04\x00\x09\x57\x50\x41\x33\x2d\x54\x45\x53" \
b"\x54\x01\x08\x8c\x12\x98\x24\xb0\x48\x60\x6c\x03\x01\x0b\x05\x04" \
b"\x00\x02\x00\x00\x2a\x01\x02\x30\x14\x01\x00\x00\x0f\xac\x04\x01" \
b"\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x08\xcc\x00\x0b\x05\x00" \
b"\x00\x2b\x00\x00\x3b\x02\x51\x00\x2d\x1a\xec\x01\x03\xff\xff\x00" \
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
b"\x00\x00\x00\x00\x3d\x16\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x08\x04\x00" \
b"\x00\x00\x01\x00\x01\x40\xf4\x01\x20\xdd\x18\x00\x50\xf2\x02\x01" \
b"\x01\x81\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62" \
b"\x32\x2f\x00"


class WiFi_Parser:
	def __init__(self, pkt):
		self.pkt = pkt
		self.elt = pkt.getlayer(Dot11Elt)

	def RadioTap_Attr(self, attr):
		if self.pkt.haslayer(RadioTap):
			return getattr(self.pkt, attr, None)

	def ssid(self):
		elt = self.elt
		while elt:
			if elt.ID == 0:
				ssid = elt.info.decode(errors="Ignore")
				return ssid if ssid else None
			elt = elt.payload.getlayer(Dot11Elt)
		return None

	def wps_info(self):
		elt = self.elt
		wps_ie_flag = False
		result = {
			'locked': False,
			'version': 1
		}

		while elt:
			if elt.ID == 221 and elt.info[:4] == b'\x00\x50\xf2\x04':
				wps_ie_flag = True
				locked_offset = elt.info.find(b'\x10\x57')
				if elt.info[locked_offset +4] == 0x01:
					result['locked'] = True
				
				UUID_E_Offset = elt.info.find(b'\x10\x47')
				RF_Bands_offset = elt.info.find(b'\x10\x3c')
				vendor_ext_offset = elt.info.find(b'\x10\x49')
				vendor2_0_ext_offset = elt.info[vendor_ext_offset:].find(b'\x00\x01\x20')

				if UUID_E_Offset and RF_Bands_offset and vendor2_0_ext_offset:
					result["version"] = 2

			elt = elt.payload.getlayer(Dot11Elt)

		if wps_ie_flag:
			return result

		return None

	def get_vendor_string(self):
		vendors_oui = {
			0x001018: "Broadcom",  # Broadcom
			0x00037f: "AtherosC",  # Atheros Communications
			0x001374: "AtherosC",  # Atheros Communications
			0x00B052: "AtherosC",  # Atheros Communications
			0x000c43: "RalinkTe",  # Ralink Technology, Corp.
			0x0017a5: "RalinkTe",  # Ralink Technology, Corp.
			0x00e04c: "RealtekS",  # Realtek Semiconductor Corp.
			0x00a000: "Mediatek",  # Mediatek Corp.
			0x000ce7: "Mediatek",  # Mediatek Corp.
			0x001c51: "CelenoCo",  # Celeno Communications, Inc
			0x005043: "MarvellS",  # Marvell Semiconductor, Inc.
			0x002686: "Quantenn",  # Quantenna Communications, Inc
			0x000986: "Metalink",  # Lantiq/MetaLink
			0x0050f2: "Microsof",  # Microsoft
			0xac853d: "HuaweiTe",  # Huawei Technologies Co., Ltd
			0x88124e: "Qualcomm",  # Qualcomm Atheros
			0x8cfdf0: "Qualcomm",  # Qualcomm, Inc
			0x00a0cc: "Lite-OnC",  # Lite-On Communications, Inc
			0x4045da: "SpreadTe",  # Spreadtrum Technology, Inc
			0x506f9a: "Wi-FiAli",  # Wi-Fi Aliance
			0x18fe34: "Espressi"   # Espressif Inc.
		}
		elt = self.elt
		while elt:
			if elt.ID == 221:
				if elt.len >= 6 and elt.len <= 9:
					return vendors_oui.get(elt.oui, 'Unknown')
			elt = elt.payload.getlayer(Dot11Elt)
		return 'Unknown'

	def get_rsn_info(self):
		cipher_suites = {
			0x00: "Group",
			0x01: "WEP-40",
			0x02: "TKIP",
			0x03: "WRAP",
			0x04: "CCMP",
			0x05: "WEP-104",
			0x06: "CMAC-128",
			0x07: "CMAC-128",
			0x08: "GCMP-128",
			0x09: "GCMP-256",
			0x0A: "BIP-GMAC-128",
			0x0B: "BIP-GMAC-256",
			0x0C: "BIP-CMAC-128",
			0x0D: "BIP-CMAC-256"
		}

		akm_suites = {
			0x01: "802.1X (RSNA)",
			0x02: "PSK",
			0x03: "802.1X-FT (Fast Transition)",
			0x04: "PSK-FT",
			0x05: "802.1X-PMKSA (PMSK)",
			0x06: "802.1X-PSK",
			0x07: "802.1X-TDLS",
			0x08: "SAE",
			0x09: "SAE-FT",
			0x0A: "PSK-SHA256",
			0x0B: "802.1X-SHA256",
			0x0C: "SAE-SHA384 (WPA3-Enterprise 192-bit)",
			0x0D: "802.1X-FT-SHA384"
		}

		result = {
			'group': None,
			'akm': [],
			'pairwise': []
		}

		elt = self.elt
		while elt:
			if elt.ID == 48:
				if hasattr(elt, 'group_cipher_suite'):
					result["group"] = cipher_suites.get(elt.group_cipher_suite.cipher, None)
				if hasattr(elt, 'pairwise_cipher_suites'):
					for suite in elt.pairwise_cipher_suites:
						result["pairwise"].append(cipher_suites.get(suite.cipher, None))
				if hasattr(elt, 'akm_suites'):
					for akm_list in elt.akm_suites:
						result["akm"].append(akm_suites.get(akm_list.suite, None))
			elt = elt.payload.getlayer(Dot11Elt)	

		return result
	
	def get_enc_type(self):
		rsn_info = None
		wpa_info = None
		rsn_data = None
		
		elt = self.elt
		while elt:
			if elt.ID == 48:
				rsn_info = elt.info
				rsn_data = elt
			if elt.ID == 221 and elt.info[:4] == b'\x00\x50\xF2\x01':
				wpa_info = elt.info
			elt = elt.payload.getlayer(Dot11Elt)
		
		if self.pkt[Dot11Beacon].cap & 0x10:
			return 'WEP'

		if rsn_info:
			if hasattr(rsn_data, 'akm_suites'):
				for akm_list in rsn_data.akm_suites:
					if akm_list.suite in [8, 9, 12, 13]:
						return 'WPA3'

		if rsn_info and wpa_info:
			return 'WPA/WPA2'
		
		if rsn_info:
			return 'WPA2'
		if wpa_info:
			return 'WPA'

		return 'Open'

pkt = RadioTap(beacon_raw_1)
wifi = WiFi_Parser(pkt)
print(wifi.get_enc_type())