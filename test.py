#!/usr/bin/env python3
import struct
import pcap

######################
#      RadioTap      #
######################

class RadioTap:
	def __init__(self, pkt):
		self.pkt = pkt

		'''
			RadioTap defs and names
			Note: RadioTap aligment is so crazy

			See: 
				https://www.radiotap.org/fields/defined
				https://wireless.docs.kernel.org/en/latest/en/developers/documentation/radiotap.html

		'''
		self.ieee80211_radiotap_presents_names = {
			0: 'TSFT',
			1: 'Flags',
			2: 'Rate',
			3: 'Channel',
			4: 'FHSS',
			5: 'dbm_Antenna_Signal',
			6: 'dbm_Antenna_Noise',
			7: 'Lock_Quality',
			8: 'TX_Attenuation',
			9: 'db_TX_Attenuation',
			10: 'dbm_TX_Power',
			11: 'Antenna',
			12: 'db_Antenna_Signal',
			13: 'db_Antenna_Noise',
			14: 'RX_Flags',
			15: 'TX_Flags',
			16: 'RTS_retries',
			17: 'Data_retries',
			18: 'Channel_plus',
			19: 'MCS',
			20: 'A_MPDU_Status',
			21: 'VHT_Info',
			22: 'Frame_timestamp',
			23: 'HE_Info',
			24: 'HE_MU_Info',
			25: 'RESERVED_1',
			26: 'Null_Length_PSDU',
			27: 'L_SIG',
			28: 'TLVs',
			29: 'RadioTap_NS_Next',
			30: 'Vendor_NS_Next',
			31: 'Ext'
		}

		self.ieee80211_radiotap_channel_flags_indexes = {
			'TSFT': 0,
			'Flags': 1,
			'Rate': 2,
			'Channel': 3,
			'FHSS': 4,
			'dbm_Antenna_Signal': 5,
			'dbm_Antenna_Noise': 6,
			'Lock_Quality': 7,
			'TX_Attenuation': 8,
			'db_TX_Attenuation': 9,
			'dbm_TX_Power': 10,
			'Antenna': 11,
			'db_Antenna_Signal': 12,
			'db_Antenna_Noise': 13,
			'RX_Flags': 14,
			'TX_Flags': 15,
			'RTS_retries': 16,
			'Data_retries': 17,
			'Channel_plus': 18,
			'MCS': 19,
			'A_MPDU_Status': 20,
			'VHT_Info': 21,
			'Frame_timestamp': 22,
			'HE_Info': 23,
			'HE_MU_Info': 24,
			'RESERVED_1': 25,
			'Null_Length_PSDU': 26,
			'L_SIG': 27,
			'TLVs': 28,
			'RadioTap_NS_Next': 29,
			'Vendor_NS_Next': 30,
			'Ext': 31
		}

		self.ieee80211_radiotap_freq_channels_2GHz = {
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

		self.ieee80211_radiotap_channel_flags_names = {
			0: '700MHz',
			1: '800MHz',
			2: '900MHz',
			4: 'Turbo',
			5: 'CCK',
			6: 'OFDM',
			7: '2GHz',
			8: '5GHz',
			9: 'Passive',
			10: 'Dynamic CCK-OFDM',
			11: 'GFSK',
			12: 'GSM-900MHz',
			13: 'Static Turbo',
			14: 'Half-Rate 10MHz',
			15: 'Quarter-Rate 5MHz'
		}

		self.ieee80211_radiotap_flags_names = [
			'CFP',
			'Long preamble',
			'WEP',
			'Fragmentation',
			'FCS at end',
			'Data PAD',
			'Bad FCS',
			'Short GI'
		]

		self.ieee80211_radiotap_presents_sizes_aligns = {
			0: {'size': 8, 'align': 8},    # TSFT
			1: {'size': 1, 'align': 1},    # Flags
			2: {'size': 1, 'align': 1},    # Rate
			3: {'size': 4, 'align': 2},    # Channel
			4: {'size': 2, 'align': 2},    # FHSS
			5: {'size': 1, 'align': 1},    # dbm_Antenna_Signal
			6: {'size': 1, 'align': 1},    # dbm_Antenna_Noise
			7: {'size': 2, 'align': 2},    # Lock_Quality
			8: {'size': 2, 'align': 2},    # TX_Attenuation
			9: {'size': 2, 'align': 2},    # db_TX_Attenuation
			10: {'size': 1, 'align': 1},   # dbm_TX_Power
			11: {'size': 1, 'align': 1},   # Antenna
			12: {'size': 1, 'align': 1},   # db_Antenna_Signal
			13: {'size': 1, 'align': 1},   # db_Antenna_Noise
			14: {'size': 2, 'align': 2},   # RX_Flags
			15: {'size': 2, 'align': 2},   # TX_Flags
			16: {'size': 1, 'align': 1},   # RTS_retries
			17: {'size': 1, 'align': 1},   # Data_retries
			18: {'size': 3, 'align': 1},   # MCS
			19: {'size': 8, 'align': 4},   # A_MPDU_Status
			20: {'size': 12, 'align': 2},  # VHT_Info
			21: {'size': 12, 'align': 8}   # Frame_timestamp
		}

	def return_RadioTap_Header(self):
		it_version, it_pad, it_len, it_present = struct.unpack_from('<BBHI', self.pkt, 0)
		return {
			'it_version': it_version,
			'it_pad': it_pad,
			'it_len': it_len,
			'it_present': it_present,
		}

	def return_RadioTap_presents(self):
		rt_header = self.return_RadioTap_Header()
		rt_presents_offset = 4
		presents_ext_flag = True
		rt_presents = int.from_bytes(self.pkt[rt_presents_offset:rt_presents_offset+4], 'little')
		rt_presents_all = []
		
		while presents_ext_flag:
			rt_presents = int.from_bytes(self.pkt[rt_presents_offset:rt_presents_offset+4], 'little')
			rt_presents_all.append(rt_presents)
			presents_ext_flag = rt_presents & (1 << 31)
			rt_presents_offset += 4

		return rt_presents_all
	
	def return_RadioTap_PresentsFlags(self):
		rt_presents = self.return_RadioTap_presents()
		rt_presents_len = len(rt_presents) * 4
		offset = rt_presents_len + 4
		presents = {}

		for rt_present in rt_presents:
			for bit in range(29):
				if rt_present & (1 << bit):
					align = self.ieee80211_radiotap_presents_sizes_aligns[bit]['align']
					size = self.ieee80211_radiotap_presents_sizes_aligns[bit]['size']
					offset = (offset + (align - 1)) & ~(align - 1)
					present = self.pkt[offset:offset+size]
					presents[bit] = present
					offset += size
		return presents

	def return_rt_default(self, val):
		return val

	def return_rt_INT(self, val):
		return int.from_bytes(val, 'little')

	def return_rt_Flags(self, val):
		result = []
		flags = int.from_bytes(val, 'little')
		for bit in range(8):
			if (flags & (1 << bit)):
				result.append(self.ieee80211_radiotap_flags_names[bit])
		return result

	def return_rt_Rate(self, val):
		return int.from_bytes(val, 'little') / 2

	def return_rt_Channel(self, val):
		channel_freq = int.from_bytes(val[:2], 'little')
		__channel_flags = int.from_bytes(val[2:], 'little')
		channel_flags = []

		for bit in range(16):
			if (__channel_flags & (1 << bit)):
				channel_flags.append(self.ieee80211_radiotap_channel_flags_names.get(bit))
		return {
			'channel': self.ieee80211_radiotap_freq_channels_2GHz.get(channel_freq, None),
			'frequency': channel_freq,
			'flags': channel_flags
		}

	def return_rt_dBm(self, val):
		return int.from_bytes(val, 'little', signed=True)

	def return_RadioTap_PresentFlag(self, flag):
		rt_presents =  self.return_RadioTap_PresentsFlags()
		flag_index = self.ieee80211_radiotap_channel_flags_indexes.get(flag, None)

		if not flag_index is None:
			if flag_index in rt_presents:
				handlers = {
					0: self.return_rt_INT,
					1: self.return_rt_Flags,
					2: self.return_rt_Rate,
					3: self.return_rt_Channel,
					5: self.return_rt_dBm,

					11: self.return_rt_INT
				}
				handler = handlers.get(flag_index, self.return_rt_default)
				result = handler(rt_presents.get(flag_index))
				return result
		return None


######################
#        Dot11       #
######################

class Dot11:
	def __init__(self, pkt):
		rt = RadioTap(pkt)
		rt_header = rt.return_RadioTap_Header()
		rt_length = rt_header['it_len']
		self.pkt = pkt[rt_length:]

		'''
			IEEE 802.11-2016
			9.2 MAC frame formats
			    ╰─> 9.2.4.1.3 Type and Subtype subfields		
		'''
		self.ieee80211_fc_types = {
			
			# Management Frames (Type 00 - Management)
			'IEEE80211_FC_ASSOC_REQ': 0x00,                # Association Request
			'IEEE80211_FC_ASSOC_RESP': 0x10,               # Association Response
			'IEEE80211_FC_REASSOC_REQ': 0x20,              # Reassociation Request
			'IEEE80211_FC_REASSOC_RESP': 0x30,             # Reassociation Response
			'IEEE80211_FC_PROBE_REQ': 0x40,                # Probe Request
			'IEEE80211_FC_PROBE_RESP': 0x50,               # Probe Response
			'IEEE80211_FC_TIMING_ADV': 0x60,               # Timing Advertisement
			'IEEE80211_FC_BEACON': 0x80,                   # Beacon
			'IEEE80211_FC_ATIM': 0x90,                     # ATIM
			'IEEE80211_FC_DISASSOC': 0xA0,                 # Disassociation
			'IEEE80211_FC_AUTH': 0xB0,                     # Authentication
			'IEEE80211_FC_DEAUTH': 0xC0,                   # Deauthentication
			'IEEE80211_FC_ACTION': 0xD0,                   # Action
			'IEEE80211_FC_ACTION_NOACK': 0xE0,             # Action No Ack

			# Control Frames (Type 01 - Control)
			'IEEE80211_FC_BEAMFORMING_REPORT': 0x44,       # Beamforming Report Poll
			'IEEE80211_FC_VHT_NDP_ANNOUNCE': 0x54,         # VHT NDP Announcement
			'IEEE80211_FC_CTRL_EXT': 0x64,                 # Control Frame Extension (addr3 ?)
			'IEEE80211_FC_CTRL_WRP': 0x74,                 # Control Wrapper
			'IEEE80211_FC_BLOCK_ACK_REQ': 0x84,            # Block Ack Request (BlockAckReq)
			'IEEE80211_FC_BLOCK_ACK': 0x94,                # Block Ack (BlockAck)
			'IEEE80211_FC_PS_POLL': 0xA4,                  # PS-Poll
			'IEEE80211_FC_RTS': 0xB4,                      # RTS
			'IEEE80211_FC_CTS': 0xC4,                      # CTS
			'IEEE80211_FC_ACK': 0xD4,                      # Ack
			'IEEE80211_FC_CF_END': 0xE4,                   # CF-End
			'IEEE80211_FC_CF_END_CF_ACK': 0xF4,            # CF-End +CF-Ack
			
			# Data Frames (Type 02 - Data)
			'IEEE80211_FC_DATA': 0x08,                     # Data
			'IEEE80211_FC_DATA_CF_ACK': 0x18,              # Data +CF-Ack
			'IEEE80211_FC_DATA_CF_POLL': 0x28,             # Data +CF-Poll
			'IEEE80211_FC_DATA_CF_ACK_CF_POLL': 0x38,      # Data +CF-Ack +CF-Poll
			'IEEE80211_FC_NULL_NO_DATA': 0x48,             # Null (no data)
			'IEEE80211_FC_CF_ACK_NO_DATA': 0x58,           # CF-Ack (no data)
			'IEEE80211_FC_CF_POLL_NO_DATA': 0x68,          # CF-Poll (no data)
			'IEEE80211_FC_CF_ACK_CF_POLL_NO_DATA': 0x78,   # CF-Ack +CF-Poll (no data)

			# QoS Data Frames (Type 02 - Data with QoS)
			'IEEE80211_FC_QOS_DATA': 0x88,                 # QoS Data
			'IEEE80211_FC_QOS_DATA_CF_ACK': 0x98,          # QoS Data +CF-Ack
			'IEEE80211_FC_QOS_DATA_CF_POLL': 0xA8,         # QoS Data +CF-Poll
			'IEEE80211_FC_QOS_DATA_CF_ACK_CF_POLL': 0xB8,  # QoS Data +CF-Ack +CF-Poll
			'IEEE80211_FC_QOS_NULL_NO_DATA': 0xC8,         # QoS Null (no data)
			'IEEE80211_FC_QOS_CF_POLL_NO_DATA': 0xE8,      # QoS CF-Poll (no data)
			'IEEE80211_FC_QOS_CF_ACK_CF_POLL': 0xF8,       # QoS CF-Ack +CF-Poll (no data)
		}

		self.ieee80211_fc_management_types = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0]
		self.ieee80211_fc_control_types = [0x44, 0x54, 0x64, 0x74, 0x84, 0x94, 0xA4, 0xB4, 0xC4, 0xD4, 0xE4, 0xF4]
		self.ieee80211_fc_data_types = [0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8]
		self.addr2_dot11_frames = [
				# Management
				0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 
				# Control
				0x44, 0x74, 0xA4, 0xB4, 0x84, 0x94,
				# Data
				0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8
				]
		self.addr3_dot11_frames = [
				# Management
				0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,

				# Data
				0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8
		]

		'''
			IEEE 802.11-2016
			9.2 MAC frame formats
				├─> 9.2.4.1.4 To DS and From DS subfields
				├─> 9.2.4.1.5 More Fragments subfield 
			    ├─> 9.2.4.1.6 Retry subfield
				├─> 9.2.4.1.7 Power Management subfield
				├─> 9.2.4.1.8 More Data subfield
				├─>	9.2.4.1.9 Protected Frame subfield
				╰─>	9.2.4.1.10 +HTC/Order subfield
		'''
		self.ieee80211_fc_flags = [
			
		]

	def mac2str(self, mac):
		return ':'.join(f'{b:02x}' for b in mac)

	def return_dot11_framecontrol(self):
		frame_control = int.from_bytes(self.pkt[0:2], 'little')
		frame_control_flags = self.pkt[3]

		fc_type = (frame_control >> 2) & 0b11
		fc_sub_type = (frame_control >> 4) & 0b1111
		fc_type_subtype = (fc_sub_type << 4) | (fc_type << 2)

		return fc_type_subtype
	
	def return_dot11_haslayer(self, layer):
		fc_layer = self.ieee80211_fc_types.get(layer, None)
		if not fc_layer is None:
			return fc_layer == self.return_dot11_framecontrol()
		
		return None
	
	def return_dot11_addrs(self):	
		frame_control = self.return_dot11_framecontrol()
		addrs = {}
		if frame_control in self.ieee80211_fc_types.values():
			addrs['addr1'] = self.mac2str(self.pkt[4:10])

			if frame_control in self.addr2_dot11_frames:
				addrs['addr2'] = self.mac2str(self.pkt[10:16])
			if frame_control in self.addr3_dot11_frames:
				addrs['addr3'] = self.mac2str(self.pkt[16:22])
			return addrs
		return None

interface = "radio0mon"
pkt = \
	b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x8a\x09\xa0\x00\xbf\x01" \
	b"\x00\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x40\xed\x00\x62" \
	b"\x31\x74\x40\xed\x00\x62\x31\x74\xe0\x6e\x3f\xe3\x47\x20\x80\x00" \
	b"\x00\x00\x64\x00\x31\x1c\x00\x0c\x54\x50\x2d\x4c\x69\x6e\x6b\x5f" \
	b"\x33\x31\x37\x34\x01\x08\x82\x84\x8b\x96\x12\x24\x48\x6c\x03\x01" \
	b"\x07\x05\x04\x00\x01\x00\x00\x07\x06\x52\x55\x20\x01\x0d\x23\x20" \
	b"\x01\x00\x23\x02\x3f\x00\xc3\x02\x00\x7e\x46\x05\x72\x00\x01\x00" \
	b"\x00\x33\x0a\x0b\x01\x02\x03\x04\x05\x06\x07\x08\x09\x2a\x01\x00" \
	b"\x32\x04\x0c\x18\x30\x60\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00" \
	b"\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\xdd\x31\x00\x50" \
	b"\xf2\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x02\x10\x47\x00\x10" \
	b"\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x40\xed\x00\x62\x31\x74" \
	b"\x10\x3c\x00\x01\x03\x10\x49\x00\x06\x00\x37\x2a\x00\x01\x20\x2d" \
	b"\x1a\xef\x11\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
	b"\x00\x00\x00\x00\x00\x00\x18\x04\x87\x09\x00\x3d\x16\x07\x00\x00" \
	b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
	b"\x00\x00\x00\x4a\x0e\x14\x00\x0a\x00\x2c\x01\xc8\x00\x14\x00\x05" \
	b"\x00\x19\x00\xbf\x0c\xb1\x79\xc9\x33\xfa\xff\x0c\x03\xfa\xff\x0c" \
	b"\x03\xc0\x05\x00\x00\x00\xfa\xff\x7f\x08\x01\x00\x08\x00\x00\x00" \
	b"\x00\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x80\x00\x03\xa4\x00\x00" \
	b"\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\xdd\x07\x00\x0c" \
	b"\x43\x09\x00\x00\x00\xdd\x21\x00\x0c\xe7\x08\x00\x00\x00\xbf\x0c" \
	b"\xb1\x01\xc0\x33\x2a\xff\x92\x04\x2a\xff\x92\x04\xc0\x05\x00\x00" \
	b"\x00\x2a\xff\xc3\x03\x01\x02\x02"

pkt2 = \
	b"\x00\x00\x24\x00\x2f\x40\x00\xa0\x20\x08\x00\x00\x00\x00\x00\x00" \
	b"\xfe\x67\x53\x01\x00\x00\x00\x00\x10\x02\x6c\x09\xa0\x00\xba\x00" \
	b"\x00\x00\xba\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\xd2\xaf" \
	b"\x7d\x6e\x40\x2a\xd2\xaf\x7d\x6e\x40\x2a\xf0\x30\x85\x61\xd8\x4e" \
	b"\x00\x00\x00\x00\x64\x00\x11\x85\x00\x0c\x72\x65\x61\x6c\x6d\x65" \
	b"\x20\x43\x32\x31\x2d\x59\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24" \
	b"\x03\x01\x09\x2a\x01\x00\x32\x04\x30\x48\x60\x6c\x05\x05\x01\x03" \
	b"\x00\x00\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x80\x00\x03\xa4\x4f" \
	b"\x00\x27\xa4\x4f\x00\x42\x43\x80\x00\x62\x32\x41\x00\x30\x14\x01" \
	b"\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac" \
	b"\x02\x0c\x00\xdd\x06\x40\x45\xda\x01\x02\x00\xdd\x1a\x00\x90\x4c" \
	b"\x04\x08\xbf\x0c\x31\x71\xa0\x03\xfe\xff\x00\x00\xfe\xff\x00\x00" \
	b"\xc0\x05\x00\x00\x00\xfe\xff\x2d\x1a\x2d\x01\x13\xff\x00\x00\x00" \
	b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
	b"\x00\x00\x00\x3d\x16\x09\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00" \
	b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x01\x00\x7f\x08" \
	b"\x00\x00\x00\x00\x00\x00\x00\x00\xbf\x0c\x31\x71\xa0\x03\xfe\xff" \
	b"\x00\x00\xfe\xff\x00\x00\x6e\xe1\x7d\xda"

pkt3 = \
	b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x0c\xa8\x09\xc0\x00\xbf\x01" \
	b"\x00\x00\x94\x00\x00\x00\xa8\x63\x7d\xe3\x01\x12\x7c\x0a\x3f\xa6" \
	b"\x8a\xf3\x05\x10\x10\x00\xff\xff\x00\x00\x00\x00\x00\x00"





dot11 = Dot11(pkt2)
print(dot11.return_dot11_addrs())

def packet_handler(ts, pkt):
	if b'\xa8\x63\x7d\xe3\x01\x12' in pkt:
		for i in range(len(pkt)):
			print(f'\\x{pkt[i]:02x}', end="")
	print("\n\n")
#pc = pcap.pcap(name=interface, immediate=True)
#pc.loop(0, packet_handler)
