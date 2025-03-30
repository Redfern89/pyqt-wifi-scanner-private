#!/usr/bin/env python3
import struct
import pcap

import numpy as np

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
					'''
						Как я с этим заебался..... Ебучие выравнивания
					'''
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
		result = {}
		flags = int.from_bytes(val, 'little')
		for bit in range(8):
			if (flags & (1 << bit)):
				result[bit] = self.ieee80211_radiotap_flags_names[bit]
				#result.append({
				#	bit: self.ieee80211_radiotap_flags_names[bit]
				#})
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
		self.rt_length = rt_length
		self.fcs_at_end = True if 4 in rt.return_RadioTap_PresentFlag('Flags') else False

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
		frame_control_flags = {}

		for bit in range(8):
			if _frame_control_flags & (1 << bit):
				frame_control_flags[bit] = { bit: self.ieee80211_fc_flags[bit] }
				

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

	def return_dot11_length(self):
		_len = 10 # Frame Control + Duration + Addr1
		fc_flags = self.return_dot11_framecontrol_flags()

		frame_control = self.return_dot11_framecontrol()
		if frame_control in self.addr2_dot11_frames:
			_len += 6
		if frame_control in self.addr3_dot11_frames:
			_len += 6

		#if 6 in fc_flags:
			#pass # Пока что хуй знает. Да и надо ли оно?

		if 7 in fc_flags:
			_len += 4 # Order

		_len += 2 # Sequence control


		if self.return_dot11_framecontrol() in [0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8]:
			_len += 2 # QoS Control

		if 6 in fc_flags:
			# 1
			ccmp_iv = self.pkt[_len:_len+8]
			seq_num = ((ccmp_iv[3] & 0x0F) << 8) | ccmp_iv[4]
			print(seq_num)
			print(self.return_dot11_frag_seq())
		

		return _len

	def return_dot11_offset(self):
		return self.rt_length

class Dot11Elt:
	def __init__(self, pkt):
		self.pkt = pkt
		self.dot11 = Dot11(pkt)
		dot11_offset = self.dot11.return_dot11_offset()
		dot11_length = self.dot11.return_dot11_length()
		self.elt_offset = dot11_offset + dot11_length

		self.authentication_algoritms = {
			0: 'Open system',
			1: 'Shared key',
			2: 'Fast BSS',
			3: 'SAE',
			65535: 'Vendor specific'
		}

		self.capabilities = [
			'ESS',
			'IBSS',
			'CF Pollable',
			'CF-Poll Request',
			'Privacy',
			'Short Preamble',
			'Reserved 1',
			'Reserved 2',
			'Spectrum Management',
			'QoS',
			'Short Slot Time',
			'APSD',
			'Radio Measurement',
			'Reserved 3',
			'Delayed Block Ack',
			'Immediate Block Ack'
		]

		self.reasons = {
			0: 'Reserved',                          # Reserved
			1: 'UNSPECIFIED_REASON',                # Unspecified reason
			2: 'INVALID_AUTHENTICATION',            # Previous authentication no longer valid
			3: 'LEAVING_NETWORK_DEAUT',             # HDeauthenticated because sending STA is leaving (or has left) IBSS or ESS
			4: 'REASON_INACTIVITY',                 # Disassociated due to inactivity
			5: 'NO_MORE_STAS',                      # Disassociated because AP is unable to handle all currently associated STAs
			6: 'INVALID_CLASS2_FRAME',              # Class 2 frame received from nonauthenticated STA
			7: 'INVALID_CLASS3_FRAME',              # Class 3 frame received from nonassociated STA
			8: 'LEAVING_NETWORK_DISASS',            # OCDisassociated because sending STA is leaving (or has left) BSS
			9: 'NOT_AUTHENTICATED',                 # STA requesting (re)association is not authenticated with responding STA
			10: 'UNACCEPTABLE_POWER_CA',            # PABILITYDisassociated because the information in the Power Capability element is unacceptable
			11: 'UNACCEPTABLE_SUPPORTED_CHANNELS',  # Disassociated because the information in the Supported Channels element is unacceptable
			12: 'BSS_TRANSITION_DISASSOC',          # Disassociated due to BSS transition management
			13: 'REASON_INVALID_ELEMENT',           # Invalid element, i.e., an element defined in this standard for which the content does not meet the specifications in Clause 9
			14: 'MIC_FAILURE',                      # Message integrity code (MIC) failure
			15: '4WAY_HANDSHAKE_TIMEOUT',           # s4-way handshake timeout
			16: 'GK_HANDSHAKE_TIMEOUT',             # Group key handshake timeout
			17: 'HANDSHAKE_ELEMENT_MISMATCH',       # Element in 4-way handshake different from (Re)Association Request/Probe Response/Beacon frame
			18: 'REASON_INVALID_GROUP_CIPHER',      # Invalid group cipher
			19: 'REASON_INVALID_PAIRWISE_CIPHER',   # Invalid pairwise cipher
			20: 'REASON_INVALID_AKMP',              # Invalid AKMP
			21: 'UNSUPPORTED_RSNE_VERSION',         # Unsupported RSNE version
			22: 'INVALID_RSNE_CAPABILITIES',        # Invalid RSNE capabilities
			23: '802_1_X_AUTH_FAILED',              # IEEE 802.1X authentication failed
			24: 'REASON_CIPHER_OUT_OF_POLICY',      # Cipher suite rejected because of the security policy
			25: 'TDLS_PEER_UNREACHABLE',            # TDLS direct-link teardown due to TDLS peer STA unreachable via the TDLS direct link
			26: 'TDLS_UNSPECIFIED_REASON',          # TDLS direct-link teardown for unspecified reason
			27: 'SSP_REQUESTED_DISASSOC',           # Disassociated because session terminated by SSP request
			28: 'NO_SSP_ROAMING_AGREEMENT',         # Disassociated because of lack of SSP roaming agreement
			29: 'BAD_CIPHER_OR_AKM',                # Requested service rejected because of SSP cipher suite or AKM requirement
			30: 'NOT_AUTHORIZED_THIS_LOCATION',     # Requested service not authorized in this location
			31: 'SERVICE_CHANGE_PRECLUDES_TS',      # TS deleted because QoS AP lacks sufficient bandwidth for this QoS STA due to a change in BSS service characteristics or operational mode (e.g., an HT BSS change from 40 MHz channel to 20 MHz channel)
			32: 'UNSPECIFIED_QOS_REASON',           # Disassociated for unspecified, QoS-related reason 
			33: 'NOT_ENOUGH_BANDWIDTH',             # Disassociated because QoS AP lacks sufficient bandwidth for this QoS STA
			34: 'MISSING_ACKS',                     # Disassociated because excessive number of frames need to beacknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions
			35: 'EXCEEDED_TXOP',                    # Disassociated because STA is transmitting outside the limits of its TXOPs
			36: 'STA_LEAVING',                      # Requesting STA is leaving the BSS (or resetting)
			37: 'END_TS_END_BA_END_DLS',            # Requesting STA is no longer using the stream or session
			38: 'UNKNOWN_TS_UNKNOWN_BA',            # Requesting STA received frames using a mechanism for which a setup has not been completed
			39: 'TIMEOUT',                          # Requested from peer STA due to timeout
			45: 'PEERKEY_MISMATCH',                 # Peer STA does not support the requested cipher suite
		}

	def return_dot11elt_offset(self):
		dot11_offset = self.dot11.return_dot11_offset()
		dot11_length = self.dot11.return_dot11_length()
		if self.dot11.return_dot11_haslayer('IEEE80211_FC_BEACON'):
			return dot11_offset + dot11_length +12
		if self.dot11.return_dot11_haslayer('IEEE80211_FC_PROBE_RESP'):
			return dot11_offset + dot11_length +12

		return dot11_offset + dot11_length
	
	def return_dot11elt_ies(self):
		result = {}

		dot11elt_offset = self.return_dot11elt_offset()
		if dot11elt_offset:
			if self.dot11.fcs_at_end:
				dot11elt_length = len(self.pkt) -4
			else:
				dot11elt_length = len(self.pkt)

			while (dot11elt_offset + 2 <= dot11elt_length):
				TAG_ID = self.pkt[dot11elt_offset]
				TAG_LEN = self.pkt[dot11elt_offset +1]
				TAG_INFO = self.pkt[dot11elt_offset +2:dot11elt_offset + 2 + TAG_LEN]
				
				result[TAG_ID] = {
					'info': TAG_INFO,
					'len': TAG_LEN
				}

				dot11elt_offset += 2 + TAG_LEN
		return result

	def return_dot11elt_beacon(self):
		offset = self.dot11.return_dot11_length() + self.dot11.return_dot11_offset()
		if self.dot11.return_dot11_haslayer('IEEE80211_FC_BEACON'):
			_timestamp = int.from_bytes(self.pkt[offset:offset+8], 'little')
			_interval = np.frombuffer(self.pkt[offset+8:offset+10], dtype=np.float16).newbyteorder('>')[0]
			_interval /= 10000
			_capabilities = int.from_bytes(self.pkt[offset+10:offset+12], 'little')
			capabilities = {}
			
			for bit in range(16):
				if (_capabilities & (1 << bit)):
					capabilities[bit] = self.capabilities[bit]
			
			return {
				'Timestamp': _timestamp,
				'Interval': f'{_interval:.6f}',
				'Capabilities': capabilities
			}
		
		return None

	def return_dot11elt_tags(self):
		pass

		#print(self.pkt[elt_offset:])


class PacketBuilder:
	def __init__(self):
		pass

	def mac2bin(self, mac):
		return bytes.fromhex(mac.replace(':', ''))
	
	def RadioTap(self):
		return b"\x00\x00\x0a\x00\x00\x80\x00\x00\x18\x00"

	def Dot11(self, fc, addr1, addr2=None, addr3=None, addr4=None, duration=0, frag=None, seq=None, fcflags=0, QoSControl=None, wep_iv=None, tkip_iv=None, ccmp_iv=None, ht_control=None):
		duration = (duration >> 1) & 0x7FFF 
		packet = bytearray()
		flags = 0x00

		if fcflags:
			for flag in fcflags:
				flags |= (1 << flag)

		packet.extend(struct.pack('<BBH6s', fc, flags, duration, self.mac2bin(addr1)))
		if addr2:
			packet.extend(struct.pack('<6s', self.mac2bin(addr2)))
		if addr3:
			packet.extend(struct.pack('<6s', self.mac2bin(addr3)))
		if addr4:
			packet.extend(struct.pack('<6s', self.mac2bin(addr4)))
		
		if not frag is None and not seq is None:
			frag_seq = (seq << 4) | frag
			packet.extend(struct.pack('<H', frag_seq))

		if not QoSControl is None:
			packet.extend(struct.pack('<H', QoSControl))

		if not ht_control is None:
			packet.extend(struct.pack('<I', ht_control))

		if not wep_iv is None:
			packet.extend(struct.pack('<I', wep_iv))

		if not tkip_iv is None:
			packet.extend(struct.pack('<Q', tkip_iv))

		if not ccmp_iv is None:
			packet.extend(struct.pack('<Q', ccmp_iv))

		return bytes(packet)

	def Dot11Beacon(self, timestamp=0, beacon_interval=0.00001, capabilities=0x0000):
		packet = bytearray()
		packet.extend(struct.pack('<Q', timestamp))
		packet.extend(struct.pack('<H', int(beacon_interval * 1000000 / 1024)))
		packet.extend(struct.pack('<H', capabilities))
		
		return bytes(packet)
	
	def Dot11Auth(self, algoritm=0, seq=0, status_code=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', algoritm))
		packet.extend(struct.pack('<H', seq))
		packet.extend(struct.pack('<H', status_code))

		return bytes(packet)

	def Dot11Deauth(self, reason_code=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', reason_code))

		return bytes(packet)

	def Dot11Disassoc(self, reason_code=0x0000):
		packet = bytearray()
		packet.extend(struct.pack('<H', reason_code))

		return bytes(packet)

	def Dot11AssocReq(self, capabilities=0x0000, listen_interval=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', capabilities))
		packet.extend(struct.pack('<H', listen_interval))

		return bytes(packet)

	def dot11AssocResp(self, capabilities=0x0000, status_code=0x0000, assoc_id=0x0000):
		packet = bytearray()
		packet.extend(struct.pack('<H', capabilities))
		packet.extend(struct.pack('<H', status_code))
		packet.extend(struct.pack('<H', (assoc_id & 0x3FFF)))

		return bytes(packet)
	
	def Dot11ReassocReq(self, current_ap, capabilities=0x0000, listen_interval=0):
		packet = bytearray()
		packet.append(struct.pack('<H', capabilities))
		packet.append(struct.pack('<H', listen_interval))
		packet.append(struct.pack('<H6s', self.mac2bin(current_ap)))

		return bytes(packet)
	
	def Dot11ReassocResp(self, capabilities=0x0000, status_code=0x0000, assoc_id=0x0000):
		packet = bytearray()
		packet.extend(struct.pack('<H', capabilities))
		packet.extend(struct.pack('<H', status_code))
		packet.extend(struct.pack('<H', (assoc_id & 0x3FFF)))

		return bytes(packet)		

	def Dot11Elt(self, id, info):
		packet = bytearray()
		packet.extend(struct.pack('<B', id))
		packet.extend(struct.pack('<B', len(info)))
		packet.extend(info)
	
		return bytes(packet)


