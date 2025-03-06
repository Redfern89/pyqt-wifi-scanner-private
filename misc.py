#!/usr/bin/env python3

from scapy.all import Dot11Beacon, Dot11Elt, RadioTap

class WiFi_Parser:
	def __init__(self, pkt):
		
		self.freq_channels = {
			2412: 1,
			2417: 2,
			2422: 3,
			2427: 4,
			2432: 5,
			2437: 6,
			2442: 7,
			2447: 8,
			2452: 9,
			2457: 10,
			2462: 11,
			2467: 12,
			2472: 13,
			2484: 14
		}
		
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

				if UUID_E_Offset != -1 and RF_Bands_offset != -1 and vendor2_0_ext_offset != -1:
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

		if self.pkt[Dot11Beacon].cap & 0x10:
			return 'WEP'

		return 'Open'
