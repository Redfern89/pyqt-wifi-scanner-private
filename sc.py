#!/usr/bin/env python3
#from scapy.all import *
from dot11 import Dot11Parser
import pprint
import pcap

iface = 'radio0mon'
pc = pcap.pcap(name=iface, promisc=True, immediate=True, timeout_ms=0)

bssids = {}

def signal_bar(dBm, width=25):
	# dBm обычно от -100 (ужас) до -30 (супер), нормализуем
	max_dbm = -30
	min_dbm = -100

	# clamp dBm
	dBm = max(min_dbm, min(max_dbm, dBm))

	# нормализация в 0.0 - 1.0
	ratio = (dBm - min_dbm) / (max_dbm - min_dbm)

	# количество символов в баре
	filled = int(ratio * width)
	empty = width - filled

	bar = '█' * filled + '░' * empty
	return bar

def colorize_bar(signal):
	# Простой градиент от зелёного до красного
	if signal > -60:
		return "\033[92m"  # зелёный
	elif signal > -70:
		return "\033[93m"  # жёлтый
	else:
		return "\033[91m"  # красный

def get_vendor_string(oui):
	vendors_oui = {
		b'\x00\x10\x18': "Broadcom",  # Broadcom
		b'\x00\x03\x7f': "AtherosC",  # Atheros Communications
		b'\x00\x13\x74': "AtherosC",  # Atheros Communications
		b'\x00\xb0\x52': "AtherosC",  # Atheros Communications
		b'\x00\x0c\x43': "RalinkTe",  # Ralink Technology, Corp.
		b'\x00\x17\xa5': "RalinkTe",  # Ralink Technology, Corp.
		b'\x00\xe0\x4c': "RealtekS",  # Realtek Semiconductor Corp.
		b'\x00\xa0\x00': "Mediatek",  # Mediatek Corp.
		b'\x00\x0c\xe7': "Mediatek",  # Mediatek Corp.
		b'\x00\x1c\x51': "CelenoCo",  # Celeno Communications, Inc
		b'\x00\x50\x43': "MarvellS",  # Marvell Semiconductor, Inc.
		b'\x00\x26\x86': "Quantenn",  # Quantenna Communications, Inc
		b'\x00\x09\x86': "Metalink",  # Lantiq/MetaLink
		b'\x00\x50\xf2': "Microsof",  # Microsoft
		b'\xac\x85\x3d': "HuaweiTe",  # Huawei Technologies Co., Ltd
		b'\x88\x12\x4e': "Qualcomm",  # Qualcomm Atheros
		b'\x8c\xfd\xf0': "Qualcomm",  # Qualcomm, Inc
		b'\x00\xa0\xcc': "Lite-OnC",  # Lite-On Communications, Inc
		b'\x40\x45\xda': "SpreadTe",  # Spreadtrum Technology, Inc
		b'\x50\x6f\x9a': "WiFiAlia",  # Wi-Fi Aliance
		b'\x18\xfe\x34': "Espressi"   # Espressif Inc.
	}
	return vendors_oui.get(oui, 'Unknown ')

print("\033[1;32mBSSID               Signal              RSSI            Ch  WPS  Lck   Vendor    SSID")
print("\033[1;35m-------------------------------------------------------------------------------------")

try:
	for ts, pkt in pc:
		Dot11P = Dot11Parser(pkt)
		Dot11 = Dot11P.return_Dot11()
		vendor = 'Unknown '
		wps = '- '
		lck = ' -  '

		if Dot11.fc.type_subtype == 0x80:
			Dot11Elt = Dot11P.return_Dot11Elt()
			ssid = None
			if not Dot11.addr3 in bssids:
				for elt in Dot11Elt:
					if elt.ID == 0:
						ssid = elt.INFO
						if not ssid:
							ssid = '<hidden>'
					if elt.ID == 221 and (elt.LEN >= 6 and elt.LEN <= 9):
						vendor = get_vendor_string(Dot11P.mac2bin(elt.INFO.oui))
					if elt.ID == 221 and (elt.INFO.oui == '00:50:F2' and elt.INFO.type == 4):
						wps = '1.0'
						lck = 'No '
						for ie in elt.INFO.data:
							if ie.name == 'VENDOR_EXTENSION':
								wps = '2.0'
							if ie.name == 'AP_SETUP_LOCKED':
								lck = 'Yes'

				signal = Dot11P.return_RadioTap_PresentFlag('dbm_Antenna_Signal')
				ch = Dot11P.return_RadioTap_PresentFlag('Channel').get('channel')
				rssi = signal_bar(signal)
				color = colorize_bar(signal)

				
				bssids[Dot11.addr3] = ssid

				print(f'\033[1;35m{Dot11.addr3.upper()}  \033[1;36m{signal} dBm  \033[0m[{color}{rssi}\033[0m] \033[1;31m{ch:>2}  \033[92m{wps:>2}  \033[92m{lck}   \033[1;34m{vendor}  \033[1;33m{ssid:<20}\033[0m')
except KeyboardInterrupt:
	print("Interrupted...")