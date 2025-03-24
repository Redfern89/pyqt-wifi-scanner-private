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
			'To DS',
			'From DS',
			'More fragments',
			'Retry',
			'Power management',
			'More data',
			'Protected frame',
			'+HTC/Order'
		]

	def mac2str(self, mac):
		return ':'.join(f'{b:02x}' for b in mac)

	def return_dot11_framecontrol(self):
		frame_control = int.from_bytes(self.pkt[0:2], 'little')

		fc_type = (frame_control >> 2) & 0b11
		fc_sub_type = (frame_control >> 4) & 0b1111
		fc_type_subtype = (fc_sub_type << 4) | (fc_type << 2)

		return fc_type_subtype
	
	def return_dot11_framecontrol_flags(self):
		_frame_control_flags = self.pkt[1]
		frame_control_flags = []

		for bit in range(8):
			if _frame_control_flags & (1 << bit):
				frame_control_flags.append(
					{
						bit: self.ieee80211_fc_flags[bit]
					}
				)

		return frame_control_flags
	
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
	
	def return_dot11_duration(self):
		return int.from_bytes(self.pkt[2:4], 'little') & 0x7FFF
	
	def return_dot11_frag_seq(self):
		frame_control = self.return_dot11_framecontrol()
		if frame_control in self.addr3_dot11_frames:
			frag_seq = int.from_bytes(self.pkt[22:24], 'little')
			frag = frag_seq & 0x0f
			seq = (frag_seq >> 4)
			
			return {
				'frag': frag,
				'seq': seq
			}
		return None

class Dot11Elt:
	def __init__(self, pkt):
		self.pkt = pkt


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
	b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x30\xa8\x09\xc0\x00\xc3\x01" \
	b"\x00\x00\xc4\x00\x98\x00\xa8\x63\x7d\xe3\x01\x12"

pkt4 = \
	b"\x00\x00\x15\x00\x2a\x48\x08\x00\x00\x00\xa8\x09\x80\x04\xbd\x01" \
	b"\x00\x00\x07\x00\x00\x88\x42\x54\x00\x7c\x0a\x3f\xa6\x8a\xf3\xa8" \
	b"\x63\x7d\xe3\x01\x12\xa8\x63\x7d\xe3\x01\x11\x00\xec\x00\x00\x5e" \
	b"\x30\x00\x20\x01\x00\x00\x00\xd6\x64\x09\x16\x44\xde\x3e\x9b\xfa" \
	b"\xf3\xfc\xd9\xaa\xa4\x63\x94\xbd\x1d\xb3\x68\x70\x9a\x97\x0a\x46" \
	b"\x27\x29\xf0\x98\x05\xfd\x29\xcc\x6e\xf3\x45\xf3\x05\x5a\xcd\x84" \
	b"\x6e\x55\x8c\x6d\x0b\x5f\x7b\xbd\x4b\x0b\x91\xb1\x82\x08\x3e\x21" \
	b"\x80\x0a\xb8\x7e\xcf\x14\x09\x96\x36\x51\xe2\x08\x98\xe3\x21\xc9" \
	b"\xb9\xe7\x06\x0b\xa3\x32\x1e\xe9\x76\xe9\xbc\x80\xab\x17\xaa\xa1" \
	b"\x61\x9d\x3d\xb2\x10\xbc\xda\x9c\x88\x56\x05\xcb\x46\x3a\x32\x5c" \
	b"\x91\x6d\xfc\x83\x97\xb0\x11\x00\xa7\x69\x32\x47\x0b\x67\xb7\xb8" \
	b"\xe0\x7b\x31\x49\xf4\xec\x3a\xe0\xd0\xea\xb3\x30\xba\xac\xd7\x8b" \
	b"\xd9\x20\x10\xa0\xe2\x81\x5f\xfb\x93\xc3\xee\x6b\xb7\x5a\x20\xc1" \
	b"\xb4\xac\xb8\x0b\x2b\x5c\x82\x52\xc8\x7d\x04\xf6\xef\x82\xbb\xb6" \
	b"\xb0\x31\x1a\x37\x31\x5c\x7d\xbb\x7c\xc2\xf0\x95\x44\xab\xc2\xbb" \
	b"\x89\x47\x9c\x14\xfd\xa8\xcc\xf7\x1c\x62\x74\xab\x8f\xb3\xc1\x9b" \
	b"\x27\x4f\xde\xd5\x14\xd9\x17\x2b\x21\x95\xff\x47\x0c\x68\x19\x83" \
	b"\x24\xed\xbe\x30\x6d\x47\x0c\x82\x38\xa3\xd4\xd2\xe5\xc4\xcb\x4b" \
	b"\x60\x5b\xf1\xf0\x73\x2b\x82\xde\xcc\x0e\x1c\xfa\xf9\x84\x77\x30" \
	b"\xa9\x79\x27\xe0\x35\xa5\x51\xdc\xfe\x96\x9a\x89\x9d\xdf\xc5\x62" \
	b"\xbc\x54\x6f\x76\x14\x82\x9e\x66\xdb\xce\x83\x79\x1c\x14\x36\x48" \
	b"\x95\xe2\xa7\xff\xe0\x1f\x1f\x0d\xdb\x95\x91\x8a\xfd\x0d\xbd\x5a" \
	b"\x44\x5b\x87\xd8\x3a\xe6\x3d\x44\x06\x97\x12\x0c\x1d\x40\x33\x04" \
	b"\x31\x2d\x99\xcd\xac\x5d\xfa\xa8\x42\x16\x7c\xf7\x7b\xf1\x80\x88" \
	b"\xbd\xf0\x0f\xec\x08\xab\xa6\xcf\xea\xf3\xb7\x29\x06\x37\xac\x6b" \
	b"\x56\x08\x6f\x26\x3e\x39\xcd\x5a\x17\x9f\x4d\x25\xea\x4d\xbc\x4c" \
	b"\xb6\x76\xb7\x55\x4f\x21\x29\x22\x2f\x99\x65\xd1\x1b\xc1\x52\xb5" \
	b"\x83\xb8\xc8\x5b\xa1\x05\x44\x52\xd4\x5e\xe8\x98\x5b\xb4\x99\x12" \
	b"\x64\x78\xd3\xb9\xc7\x13\x95\xf3\x1d\xb3\x18\x20\x66\x8d\x44\xe7" \
	b"\xf8\x30\x2e\xa4\x61\x01\xeb\x09\xb1\x1f\xc9\xbb\x79\xe2\x27\x42" \
	b"\x12\x42\x19\x27\x95\x9d\xd1\xdf\xdb\x25\x01\x97\x0b\xc5\xbe\x7b" \
	b"\x21\xc1\x82\x3d\x3c\xf7\x65\x4d\xe2\x8c\xca\x1d\x21\x79\xd8\x79" \
	b"\xad\xdf\x75\x22\xa2\x8b\x67\x17\x83\xb6\x34\x5b\xf8\xd0\x0e\x7e" \
	b"\xaa\x17\x3d\xf3\xda\x95\x77\x26\xc1\x86\x83\x48\x5d\x65\x2a\x70" \
	b"\xec\xd7\x03\x09\xbf\x05\xed\xf1\x48\xb0\xc7\x12\x81\xd0\x0f\x47" \
	b"\x48\xa0\x28\x38\x9b\x2b\x52\xd2\x90\x18\x1c\xd3\x4e\xdb\xbd\xff" \
	b"\x52\xd3\xfd\xcb\x22\x8f\x74\x16\x9b\xaf\x6b\x91\x34\x89\xd1\xbf" \
	b"\xdc\x13\x2d\xd6\xc8\x8c\x39\xae\x70\xb8\x25\x7d\xc5\xbf\xf8\x24" \
	b"\x23\x6d\xf7\xaa\x28\xdb\xc6\x4a\x8e\x6c\x1b\xaf\x3c\xc9\xb6\xd6" \
	b"\x43\xa8\xba\x88\x7f\x50\x26\x58\x55\x4f\xa5\x28\xb3\xc6\x0f\xb9" \
	b"\x6a\x83\x46\x8c\x89\x49\xb3\x26\x83\x09\x1a\x3b\x53\x5b\xcf\xb8" \
	b"\xe8\x7b\xbf\xf1\x4a\xb8\x84\x2a\xc7\x2f\x4b\xee\xb4\xc1\xd7\xa8" \
	b"\x2c\x04\xb5\x07\xb2\x1c\xd7\x37\x9c\xf5\x96\xa1\xab\x4b\x9c\xfb" \
	b"\x30\x95\x86\xf5\x8f\x88\x9a\x1e\xb6\x82\x7e\xc7\xab\x5b\x24\xcb" \
	b"\xa3\xd2\x03\x7f\x2c\x3d\xab\x5d\xac\x21\x77\x07\xf5\x74\x80\x1c" \
	b"\xfa\xc5\x16\x50\xd7\x96\x6a\x32\x1d\x0e\xbc\xdd\x5a\xa8\x82\x58" \
	b"\x7a\x7f\x21\xcd\x4b\x35\x68\xe5\xc2\x50\x69\x8d\xec\x27\x54\xb4" \
	b"\x0a\xf7\x28\xd9\xa5\x15\x1b\x60\x34\xc5\x66\xe0\x2f\xb3\xd2\xab" \
	b"\xe0\xe0\x4d\x76\x18\xcf\x4f\xb4\xce\x12\x04\xcf\xa2\xc8\x37\x47" \
	b"\x7d\xda\xa2\x96\x29\x21\x20\x4e\x42\xcc\xd2\x35\x28\x44\x5f\xac" \
	b"\x81\x48\x48\xf4\x34\x12\x0e\x6d\x08\xcb\x24\x25\xcb\x34\x7e\xbc" \
	b"\x93\x27\xb4\x7d\xe1\xb0\xa1\x32\xfe\x01\x9c\x27\x05\x15\xbe\x9e" \
	b"\x18\x33\x24\x28\xec\x0a\x0a\xcd\x52\x62\xb5\xe7\x10\x1c\x02\xd9" \
	b"\xf2\x2b\x66\x3e\xb3\x99\x34\xcc\x62\xb2\x4b\x2b\xa1\x88\xc4\x2a" \
	b"\x05\x8f\xc1\x7c\x11\x7d\xce\xb1\xd1\x75\x06\x14\x07\xa9\xe6\x36" \
	b"\xfe\x80\x20\xa1\x55\x74\x46\x9d\x1c\x63\x17\xad\x38\x0a\x4e\x5f" \
	b"\x24\x77\x9a\x21\x63\x6d\xb3\x91\xaf\xb6\x85\x51\x24\x50\x96\xed" \
	b"\x19\x3c\xd9\x27\xdd\x07\xc4\x0c\x66\xbf\x45\x4b\xf5\x7f\x04\xdf" \
	b"\x44\xd1\x48\x72\x07\x9e\x38\xf8\x81\x8b\xd0\x0a\x8a\xc8\xc5\xa7" \
	b"\x80\xe5\x06\xaa\xa3\x49\x9a\x3b\xe1\x92\x89\x71\x38\x81\xc8\x7b" \
	b"\xf9\x29\x7f\x62\xef\x2c\xfb\xf9\xe1\x8f\x36\xf8\x64\x6b\x7a\xa1" \
	b"\x63\xfb\x58\x69\xf4\x46\xcb\xa7\xa6\x43\x3e\x47\x4b\x50\x3c\xf4" \
	b"\xe0\xdf\x30\x24\x72\x56\x9b\x05\x74\xde\xc5\xc2\xfd\xf1\x8a\xd8" \
	b"\x3d\x5d\x02\x9f\x68\x7f\x35\xba\xb7\x34\x49\xbd\x6e\x19\x52\x5a" \
	b"\xb2\x22\xe9\x7c\x70\x16\x87\x77\x85\xfe\x2c\xdb\xe0\x93\xfc\xc3" \
	b"\x3d\xcc\x7c\x48\x81\xb8\xba\xe2\x3b\x8c\x38\x6c\xb4\x8d\x9a\xbc" \
	b"\x02\xd1\xe0\x3b\xb8\x74\x82\x62\xe7\xa3\x41\xca\x35\xcd\x5e\x19" \
	b"\x0f\xba\x69\x88\x70\xa5\x1f\x50\x26\x09\x40\x69\xdf\x10\x79\xad" \
	b"\xa2\x62\xa0\x93\xba\x8d\xd2\x69\x6e\x8d\xea\xe0\x37\x18\x15\x29" \
	b"\xd7\x8c\xd9\x46\x61\x3b\x68\x33\x68\xa1\x6b\xac\x27\x18\x9a\x99" \
	b"\x94\x21\xdc\x97\xf2\x8d\x34\x09\xec\xe7\xf5\x88\x64\xca\x49\x9d" \
	b"\x0a\x9d\xbd\x98\x9a\xe4\x91\xa4\xc8\x33\x9e\x5d\xa9\x03\x34\x1f" \
	b"\x4f\xd5\xa9\x37\xbe\x92\x65\xd8\x25\x52\x5b\x2f\x9c\x6d\xb7\x62" \
	b"\x80\xd1\x56\x91\x98\x95\x2c\x96\xa0\x7c\x00\x7e\x7f\xb7\x65\x9b" \
	b"\xa7\x74\xb1\xdd\xf8\xc3\x8b\x08\xfa\x0b\xa1\xa0\xc5\xd8\xc8\xae" \
	b"\x97\x74\x6f\x9f\x2c\xcc\x85\x35\x6f\x0a\x1b\x55\x6d\xa1\xb3\x0a" \
	b"\x87\xfc\xbe\xa5\xbb\x86\xae\x46\x93\xba\x2c\xe6\xe7\x95\xe5\x76" \
	b"\xe5\x20\xcb\x14\x9f\x1f\x65\xfa\x7d\x18\xdf\x82\xa0\xa4\x90\x25" \
	b"\x33\x87\x21\x8b\x77\x01\xff\xc4\xb9\x00\x2b\xad\x24\x5e\xcf\x56" \
	b"\x41\x66\xe5\x28\x53\xab\x47\xb5\x3c\x58\x41\x33\xa6\xac\x48\xca" \
	b"\xd3\x6f\xc9\xe6\x59\x6c\x4a\xa7\xf5\x37\x60\x69\x1b\x20\xea\x47" \
	b"\xaa\x3f\x7d\x7a\x91\x55\x7d\xd5\x2f\xfa\x85\xeb\x4e\x46\xdb\xa0" \
	b"\x43\x63\xb0\xf4\x20\xa9\xb3\x09\x12\xd1\x43\x1c\x0b\xf2\xb7\xd9" \
	b"\x1f\x41\x21\xf9\xff\x7e\x87\x91\x45\x1c\x79\x68\x56\xb6\xb2\xad" \
	b"\xab\xa7\xb5\x58\x5d\x32\x29\xf8\x33\x1f\x5c\x89\x19\x45\x37\x3f" \
	b"\xab\xa1\x28\xe5\x77\xab\xf1\xdf\xd1\xf5\x4f\xcf\xe1\x22\x2d\xae" \
	b"\x2b\x51\x06\x4c\x34\x68\x72\x88\x35\xb8\x2c\x5a\x24\x18\x8e\xbe" \
	b"\xb1\xdf\x8c\x9f\x7a\xdd\xba\x8e\x42\x4c\xeb\xf9\xc5\x97\x76\x52" \
	b"\xe0\x3c\x50\x7e\x20\x33\xef\xa1\x7d\xcb\x5c\xca\x31\x45\x75\x89" \
	b"\x02\xbd\x1b\x02\x80\xa8\xbe\x65\x96\x9d\x92\x16\x48\x19\xb8\x55" \
	b"\x4b\x89\x15\x03\xb8\xb3\x9c\xeb\xd2\xde\xf1\xd9\xfa\xc9\xab\xab" \
	b"\x03\x18\x9c\xee\x0f\x6c\xf2\xfa\x97\x7a\xa1\x82\xa2\x63\x52\x78" \
	b"\xb4\x0c\x9c\x7d\xd1\xf6\x54\x8e\xb9\xd6\x91\xc1\x25\x24\x4a\x0c" \
	b"\xe7\xd5\x45\x71\x3d\x4b\xf9\xcd\xea\xd2\xe9\xb5\x0a\xaf\x38\x1d" \
	b"\xc5\x51\xb2\x09\x43\x07\xba\x35\xa3\xeb\x21\x73\xb6\x4b\x6a\xca" \
	b"\x7b\xb5\x6d\x85\x08\x0c\x69\x7a\xaa\x03\x80\x5e\xd3\x05\x04\xed" \
	b"\x9b\xbe\x00\x6e\x5f\x28\xc9\xf9\x71\x0a\x38\x84\x2a\xb7\xa4\xe0" \
	b"\xaf\x23\x8a\x62\x26\xc1\x35\xdb\x37\x0f\xfa\x3c\x0d\xa3\x71\x75" \
	b"\x4b\xad\xa6"



dot11 = Dot11(pkt4)
print(dot11.return_dot11_framecontrol_flags())

def packet_handler(ts, pkt):
	if b'\xa8\x63\x7d\xe3\x01\x12' in pkt:
		for i in range(len(pkt)):
			print(f'\\x{pkt[i]:02x}', end="")
	print("\n\n")
#pc = pcap.pcap(name=interface, immediate=True)
#pc.loop(0, packet_handler)
