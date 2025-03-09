#!/usr/bin/env python3

import os
import subprocess
import re
import time

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
						cipher = cipher_suites.get(suite.cipher, None)
						if not cipher in result["pairwise"]:
							result["pairwise"].append(cipher)
				if hasattr(elt, 'akm_suites'):
					for akm_list in elt.akm_suites:
						akm = akm_suites.get(akm_list.suite, None)
						if not akm in result["akm"]:
							result["akm"].append(akm)
			if elt.ID == 221 and elt.info[:4] == b'\x00\x50\xf2\x01':
				if hasattr(elt, 'pairwise_cipher_suites'):
					for suite in elt.pairwise_cipher_suites:
						cipher = cipher_suites.get(suite.cipher, None)
						if not cipher in result["pairwise"]:
							result["pairwise"].append(cipher)
				if hasattr(elt, 'akm_suites'):
					for akm_list in elt.akm_suites:
						akm = akm_suites.get(akm_list.suite, None)
						if not akm in result["akm"]:
							result["akm"].append(akm)
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
						return ['WPA3']

		if rsn_info and wpa_info:
			return ['WPA', 'WPA2']
		
		if rsn_info:
			return ['WPA2']
		if wpa_info:
			return ['WPA']

		if self.pkt[Dot11Beacon].cap & 0x10:
			return ['WEP']

		return ['Open']
	
class WiFiPhyManager:
	def __init__(self):
		self.iface_types = {
			0: 'Unknown',
			1: 'Station',
			802: 'Ad-Hoc',
			803: 'Monitor',
			804: 'Mesh (802.11s)',
			805: 'P2P (Direct GO)',
			806: 'P2P Client'
		}

		self.iface_states = {
			0: 'DOWN',
			1: 'UP'
		}

	def handle_lost_phys(self):
		devices = {}
		if os.path.exists('/sys/class/ieee80211'):
			phys = os.listdir('/sys/class/ieee80211')
			for phydev in phys:
				devices[phydev] = {
					'phydev': phydev,
					'interface': self.iface_name_by_phy(phydev),
					'mac': self.get_phy_mac(phydev),
					'driver': self.get_phy_driver(phydev),
					'chipset': self.get_phy_chipset(phydev),
					'state': self.get_phy_state(phydev),
					'mode': self.get_phy_mode(phydev),
					'channels': self.get_phy_supported_channels(phydev),
				}

		return devices

	def iface_exists(self, iface):
		return os.path.exists(f"/sys/class/net/{iface}")

	def iface_name_by_phy(self, phy):
		if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net"):
			dir_list = os.listdir(f"/sys/class/ieee80211/{phy}/device/net")
			uevent_path = f"/sys/class/ieee80211/{phy}/device/net/{dir_list[0]}/uevent"
			if os.path.exists(uevent_path):
				with open(uevent_path, "r") as uevent:
					data = dict(line.strip().split('=') for line in uevent if "=" in line)
					return data.get('INTERFACE')
		return None

	def get_phy_state(self, phy):
		iface = self.iface_name_by_phy(phy)
		iface_data = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
		return 'UP' in iface_data.stdout

	def get_iface_state(self, iface):
		iface_data = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
		return 'UP' in iface_data.stdout


	def set_phy_link(self, phy, state):
		iface = self.iface_name_by_phy(phy)

		if state in ['up', 'down']:
			subprocess.run(['ip', 'link', 'set', iface, state])

	def get_phy_driver(self, phy):
		if os.path.exists(f"/sys/class/ieee80211/{phy}/device/uevent"):
			with open(f"/sys/class/ieee80211/{phy}/device/uevent", "r") as uevent:
				data = dict(line.strip().split('=') for line in uevent if "=" in line)
				return data.get('DRIVER')
		return None


	def get_phy_chipset(self, phy):
		iface = self.iface_name_by_phy(phy)
		if os.path.exists(f"/sys/class/ieee80211/{phy}/device/modalias"):
			modalias = open(f"/sys/class/ieee80211/{phy}/device/modalias", "r").read()			
			bus = modalias[:3] # шина

			if bus == 'pci':
				businfo = subprocess.run(['ethtool', '-i', iface], capture_output=True, text=True)
				for line in businfo.stdout.splitlines():
					match = re.search('bus-info: [0-9]{4}:(.+)', line) 
					if match:
						bus_id = match.group(1)
						if bus_id:
							lspci = subprocess.run(['lspci'], capture_output=True, text=True)
							for pcidev in lspci.stdout.splitlines():
								found_busid = pcidev[:7]
								if found_busid == bus_id:
									match = re.search(fr'{bus_id} .+: (.+)', pcidev)
									if match:
										chipset = match.group(1).replace('Wireless Adapter', '').strip()
										chipset = match.group(1).replace('Wireless Network Adapter', '').strip()
										return chipset

			if bus == 'usb':
				match = re.search(fr'{bus}:v([0-9A-Fa-f]{{4}})p([0-9A-Fa-f]{{4}})', modalias)
				if match:
					vid = match.group(1)
					pid = match.group(2)
					vid_pid = f"{vid}:{pid}".lower()
					lsusb = subprocess.run(['lsusb'], capture_output=True, text=True)
					for line in lsusb.stdout.splitlines():
						match = re.search(fr'ID {vid_pid} (.+)', line)
						if match:
							chipset = match.group(1).replace('Wireless Adapter', '').strip()
							return chipset

		return None

	def get_phy_mode(self, phy):
		iface = self.iface_name_by_phy(phy)
		if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net/{iface}/type"):
			iface_type = int(open(f"/sys/class/ieee80211/{phy}/device/net/{iface}/type", "r").read().strip())
			return int(iface_type)		
		return 0

	def set_phy_80211_monitor(self, phy):
		if self.get_phy_mode(phy) != 803:
			iface = self.iface_name_by_phy(phy)
			self.set_phy_link(phy, 'down')
			time.sleep(1)
			if self.get_phy_state(phy) == False:
				print(f"{phy} {iface} is down state")
				iface_index = 0
				mon_iface = f"radio{iface_index}mon"

				while self.iface_exists(mon_iface):
					mon_iface = f"radio{iface_index}mon"
					iface_index += 1

				subprocess.run(['iw', 'phy', phy, 'interface', 'add', mon_iface, 'type', 'monitor'], capture_output=True, text=True)
				subprocess.run(['iw', 'dev', iface, 'del'], capture_output=True, text=True)
				time.sleep(1)
				
				if self.get_phy_mode(phy) == 803:
					self.set_phy_link(phy, 'up')
				else:
					subprocess.run(['iw', 'dev', mon_iface, 'del'], capture_output=True, text=True)
		
	def set_phy_80211_station(self, phy):
		if self.get_phy_mode(phy) == 803:
			iface = self.iface_name_by_phy(phy)
			self.set_phy_link(phy, 'down')
			if self.get_phy_state(phy) == False:
				station_iface = iface[:-3]
				subprocess.run(['iw', 'phy', phy, 'interface', 'add', station_iface, 'type', 'station'], capture_output=True, text=True)
				time.sleep(1)
				if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net"):
					for phy_iface in os.listdir(f"/sys/class/ieee80211/{phy}/device/net"):
						mac_80211_type_path = f"/sys/class/ieee80211/{phy}/device/net/{phy_iface}/type"
						if os.path.exists(mac_80211_type_path):
							mac_80211_type = int(open(mac_80211_type_path, "r").read().strip())
							if mac_80211_type == 1:
								time.sleep(1)
								subprocess.run(['iw', 'dev', iface, 'del'], capture_output=True, text=True)

	def get_phy_mac(self, phy):
		if os.path.exists(f"/sys/class/ieee80211/{phy}/macaddress"):
			return open(f"/sys/class/ieee80211/{phy}/macaddress", "r").read().strip()
		return 'Unknown'

	def switch_iface_channel(self, interface, ch):
		subprocess.run(["iwconfig", interface, "channel", str(ch)], capture_output=True, text=True)

	def get_phy_supported_channels(self, phydev):
		channels_data = subprocess.run(['iw', 'phy', phydev, 'channels'], capture_output=True, text=True).stdout
		channels = []
		for line in channels_data.splitlines():
			match = re.search('MHz \[(\d+)\]', line)
			if match:
				channels.append(int(match.group(1)))			
		return channels

#wifi = WiFiPhyManager()
#print(wifi.handle_lost_phys())