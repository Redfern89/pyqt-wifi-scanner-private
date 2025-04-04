#!/usr/bin/env python3
import struct
import pcap

import numpy as np

######################
#       Utils        #
######################
class IEEE80211_Utils:
	def mac2str(self, mac):
		return ':'.join(f'{b:02x}' for b in mac)
	
	def mac2bin(self, mac):
		return bytes.fromhex(mac.replace(':', '').replace('-', ''))
	
	def getKeyByVal(self, dict, val):
		return {v: k for k, v in dict.items()}.get(val, None)
	
	def makeFlagsField(self, flags_list, flags):
		result = 0

		if not flags:
			return 0x00

		if isinstance(flags_list, list):
			for flag in flags:
				if flag in flags_list:
					flag_bit = flags_list.index(flag)
					result |= (1 << flag_bit)
			return result

		if isinstance(flags_list, dict):
			for flag in flags:
				flag_bit = self.getKeyByVal(flags_list, flag)
				if flag_bit:
					result |= (1 << flag_bit)

			return result

		return 0x00
	
	def get_struct_format(self, size, signed):
		formats = {1: 'b' if signed else 'B', 2: 'h' if signed else 'H', 4: 'i' if signed else 'I', 8: 'q' if signed else 'Q'}
		return formats.get(size, f'{size}s')  # Если что-то не так — закинем как строку



######################
#    Definitions     #
######################
class IEEE80211_DEFS:
	'''
		RadioTap defs and names
		Note: RadioTap aligment is so crazy
		
		See: 
			https://www.radiotap.org/fields/defined
			https://wireless.docs.kernel.org/en/latest/en/developers/documentation/radiotap.html
	'''
	ieee80211_radiotap_presents_names = {
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

	'''
		https://www.radiotap.org/fields/Channel.html
	'''
	ieee80211_radiotap_freq_channels_2GHz = {
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

	'''
		https://www.radiotap.org/fields/Channel.html
	'''
	ieee80211_radiotap_channel_flags_names = {
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

	ieee80211_radiotap_channel_flags_keys = {
		'700MHz': 0,
		'800MHz': 1,
		'900MHz': 2,
		'Turbo': 4,
		'CCK': 5,
		'OFDM': 6,
		'2GHz': 7,
		'5GHz': 8,
		'Passive': 9,
		'Dynamic CCK-OFDM': 10,
		'GFSK': 11,
		'GSM-900MHz': 12,
		'Static Turbo': 13,
		'Half-Rate 10MHz': 14,
		'Quarter-Rate 5MHz': 15
	}

	'''
		https://www.radiotap.org/fields/Flags.html
	'''
	ieee80211_radiotap_flags_names = [
		'CFP',
		'Long preamble',
		'WEP',
		'Fragmentation',
		'FCS at end',
		'Data PAD',
		'Bad FCS',
		'Short GI'
	]

	'''
		https://www.radiotap.org/fields/defined
	'''
	ieee80211_radiotap_presents_sizes_aligns = {
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


	'''
		IEEE 802.11-2016
		9.2 MAC frame formats
		    ╰─> 9.2.4.1.3 Type and Subtype subfields		
	'''
	ieee80211_fc_types = {
		
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
	ieee80211_fc_flags = [
		'To DS',
		'From DS',
		'More fragments',
		'Retry',
		'Power management',
		'More data',
		'Protected frame',
		'+HTC/Order'
	]

	'''
		IEEE 802.11-2016
		   9.4 Management and Extension frame body components
		      ╰─> 9.4.1 Fields that are not elements
			        ╰─> 9.4.1.1 Authentication Algorithm Number field
	'''
	ieee80211_authentication_algoritms = {
		0: 'Open system',
		1: 'Shared key',
		2: 'Fast BSS',
		3: 'SAE',
		65535: 'Vendor specific'
	}

	'''
		IEEE 802.11-2016
		   9.4 Management and Extension frame body components
		      ╰─> 9.4.1 Fields that are not elements
			        ╰─> 9.4.1.4 Capability Information field
	'''
	ieee80211_capabilities = [
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


	'''
		IEEE 802.11-2016
		   9.4 Management and Extension frame body components
		      ╰─> 9.4.1 Fields that are not elements
			        ╰─> 9.4.1.7 Reason Code field
	'''
	ieee80211_reason_codes = {
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

	'''
		IEEE 802.11-2016
		   9.4 Management and Extension frame body components
		      ╰─> 9.4.1 Fields that are not elements
			        ╰─> 9.4.1.9 Status Code field
	'''
	ieee80211_status_codes = {
		0: "SUCCESS",                                       # Successful
		1: "REFUSED_REASON_UNSPECIFIED",                    # Unspecified failure
		2: "TDLS_REJECTED_ALTERNATIVE_PROVIDED",            # TDLS wakeup schedule rejected but alternative schedule provided
		3: "TDLS_REJECTED",                                 # TDLS wakeup schedule rejected
		5: "SECURITY_DISABLED",                             # Security disabled
		6: "UNACCEPTABLE_LIFETIME",                         # Unacceptable lifetime
		7: "NOT_IN_SAME_BSS",                               # Not in same BSS
		10: "REFUSED_CAPABILITIES_MISMATCH",                # Cannot support all requested capabilities
		11: "DENIED_NO_ASSOCIATION_EXISTS",                 # Reassociation denied due to inability to confirm association
		12: "DENIED_OTHER_REASON",                          # Association denied due to reason outside the scope of this standard
		13: "UNSUPPORTED_AUTH_ALGORITHM",                   # Responding STA does not support the specified authentication algorithm
		14: "TRANSACTION_SEQUENCE_ERROR",                   # Authentication transaction sequence error
		15: "CHALLENGE_FAILURE",                            # Authentication rejected because of challenge failure
		16: "REJECTED_SEQUENCE_TIMEOUT",                    # Authentication rejected due to timeout
		17: "DENIED_NO_MORE_STAS",                          # Association denied because AP is unable to handle additional associated STAs
		18: "REFUSED_BASIC_RATES_MISMATCH",                 # Association denied due to unsupported basic rates
		19: "DENIED_NO_SHORT_PREAMBLE_SUPPORT",             # Association denied due to no short preamble support
		22: "REJECTED_SPECTRUM_MANAGEMENT_REQUIRED",        # Association request rejected because Spectrum Management capability is required
		23: "REJECTED_BAD_POWER_CAPABILITY",                # Association request rejected due to unacceptable power capability
		24: "REJECTED_BAD_SUPPORTED_CHANNELS",              # Association request rejected due to unacceptable supported channels
		25: "DENIED_NO_SHORT_SLOT_TIME_SUPPORT",            # Association denied due to no short slot time support
		27: "DENIED_NO_HT_SUPPORT",                         # Association denied due to no HT support
		28: "R0KH_UNREACHABLE",                             # R0KH unreachable
		29: "DENIED_PCO_TIME_NOT_SUPPORTED",                # Association denied due to unsupported PCO time
		30: "REFUSED_TEMPORARILY",                          # Association request rejected temporarily; try again later
		31: "ROBUST_MANAGEMENT_POLICY_VIOLATION",           # Robust management frame policy violation
		32: "UNSPECIFIED_QOS_FAILURE",                      # Unspecified QoS-related failure
		33: "DENIED_INSUFFICIENT_BANDWIDTH",                # QoS AP or PCP has insufficient bandwidth
		34: "DENIED_POOR_CHANNEL_CONDITIONS",               # Association denied due to excessive frame loss rates
		35: "DENIED_QOS_NOT_SUPPORTED",                     # QoS association denied due to lack of QoS support
		37: "REQUEST_DECLINED",                             # The request has been declined
		38: "INVALID_PARAMETERS",                           # Request contains invalid parameters
		39: "REJECTED_WITH_SUGGESTED_CHANGES",              # Allocation or TS not created but a suggested change is provided
		40: "STATUS_INVALID_ELEMENT",                       # Invalid element
		41: "STATUS_INVALID_GROUP_CIPHER",                  # Invalid group cipher
		42: "STATUS_INVALID_PAIRWISE_CIPHER",               # Invalid pairwise cipher
		43: "STATUS_INVALID_AKMP",                          # Invalid AKMP
		44: "UNSUPPORTED_RSNE_VERSION",                     # Unsupported RSNE version
		45: "INVALID_RSNE_CAPABILITIES",                    # Invalid RSNE capabilities
		46: "STATUS_CIPHER_OUT_OF_POLICY",                  # Cipher suite rejected due to security policy
		47: "REJECTED_FOR_DELAY_PERIOD",                    # TS not created but may be possible after a delay
		48: "DLS_NOT_ALLOWED",                              # Direct link not allowed in the BSS by policy
		49: "NOT_PRESENT",                                  # Destination STA is not present within this BSS
		50: "NOT_QOS_STA",                                  # Destination STA is not a QoS STA
		51: "DENIED_LISTEN_INTERVAL_TOO_LARGE",             # Association denied due to large listen interval
		52: "STATUS_INVALID_FT_ACTION_FRAME_COUNT",         # Invalid FT Action frame count
		53: "STATUS_INVALID_PMKID",                         # Invalid PMKID
		54: "STATUS_INVALID_MDE",                           # Invalid MDE
		55: "STATUS_INVALID_FTE",                           # Invalid FTE
		56: "REQUESTED_TCLAS_NOT_SUPPORTED",                # Requested TCLAS processing is not supported
		57: "INSUFFICIENT_TCLAS_PROCESSING_RESOURCES",      # Insufficient TCLAS processing resources
		58: "TRY_ANOTHER_BSS",                              # Suggested BSS transition
		59: "GAS_ADVERTISEMENT_PROTOCOL_NOT_SUPPORTED",     # GAS Advertisement Protocol not supported
		60: "NO_OUTSTANDING_GAS_REQUEST",                   # No outstanding GAS request
		61: "GAS_RESPONSE_NOT_RECEIVED_FROM_SERVER",        # GAS Response not received from Advertisement Server
		62: "GAS_QUERY_TIMEOUT",                            # GAS Query Response timeout
		63: "GAS_QUERY_RESPONSE_TOO_LARGE",                 # GAS Response exceeds response length limit
		64: "REJECTED_HOME_WITH_SUGGESTED_CHANGES",         # Request refused due to home network limitations
		65: "SERVER_UNREACHABLE",                           # Advertisement Server in network is unreachable
		67: "REJECTED_FOR_SSP_PERMISSIONS",                 # Request refused due to SSPN permissions
		68: "REFUSED_UNAUTHENTICATED_ACCESS_NOT_SUPPORTED", # Unauthenticated access not supported
		72: "INVALID_RSNE",                                 # Invalid RSNE contents
		73: "U_APSD_COEXISTENCE_NOT_SUPPORTED",             # U-APSD coexistence not supported
		76: "ANTI_CLOGGING_TOKEN_REQUIRED",                 # Authentication rejected due to Anti-Clogging Token requirement
		77: "UNSUPPORTED_FINITE_CYCLIC_GROUP",              # Unsupported finite cyclic group
		78: "CANNOT_FIND_ALTERNATIVE_TBTT",                 # Unable to find an alternative TBTT
		79: "TRANSMISSION_FAILURE",                         # Transmission failure
		82: "REJECTED_WITH_SUGGESTED_BSS_TRANSITION",       # Rejected with suggested BSS transition
		85: "SUCCESS_POWER_SAVE_MODE",                      # Success, destination STA in power save mode
		92: "REFUSED_EXTERNAL_REASON",                      # (Re)Association refused due to external reason
		93: "REFUSED_AP_OUT_OF_MEMORY",                     # (Re)Association refused due to AP memory limits
		94: "REJECTED_EMERGENCY_SERVICES_NOT_SUPPORTED",    # Emergency services not supported at AP
		95: "QUERY_RESPONSE_OUTSTANDING",                   # GAS query response not yet received
		96: "REJECT_DSE_BAND",                              # Reject due to transition to a DSE band
		99: "DENIED_WITH_SUGGESTED_BAND_AND_CHANNEL",       # Association denied, but suggested band and channel provided
		104: "DENIED_VHT_NOT_SUPPORTED",                    # Association denied due to lack of VHT support
		105: "ENABLEMENT_DENIED",                           # Enablement denied
		107: "AUTHORIZATION_DEENABLED"                      # Authorization deenabled
	}


	ieee80211_wifialiance_ids = {
		0x104a: 'VERSION',
		
	}



######################
#      RadioTap      #
######################

class RadioTap(IEEE80211_DEFS, IEEE80211_Utils):
	def __init__(self, pkt):
		self.pkt = pkt

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
		flag_index =  self.ieee80211_radiotap_presents_names.get(flag, None) #self.ieee80211_radiotap_channel_flags_indexes.get(flag, None)
		
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
class Dot11(IEEE80211_DEFS, IEEE80211_Utils):
	def __init__(self, pkt):
		rt = RadioTap(pkt)
		rt_header = rt.return_RadioTap_Header()
		rt_length = rt_header['it_len']
		self.pkt = pkt[rt_length:]
		self.rt_length = rt_length
		self.fcs_at_end = False
		rt_flags = rt.return_RadioTap_PresentFlag('Flags')
		if rt_flags:
			self.fcs_at_end = True if 4 in rt_flags else False

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

class Dot11Elt(IEEE80211_DEFS, IEEE80211_Utils):
	def __init__(self, pkt):
		self.pkt = pkt
		self.dot11 = Dot11(pkt)
		dot11_offset = self.dot11.return_dot11_offset()
		dot11_length = self.dot11.return_dot11_length()
		self.elt_offset = dot11_offset + dot11_length

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

	def return_EAPOL_Data(self):
		dot11_offset = self.dot11.return_dot11_offset()
		dot11_length = self.dot11.return_dot11_length()		
		offset = dot11_offset + dot11_length
		dot11_fc_flags = self.dot11.return_dot11_framecontrol_flags()
		fc = self.dot11.return_dot11_framecontrol()
		
		# Not protected flag and FrameControl = Data / QoS Data wthout NULL-function
		if not 6 in dot11_fc_flags and fc in [0x08, 0x18, 0x28, 0x38, 0x88, 0x98,0xA8, 0xB8]:
			# LLC / SNAP, Control = UI (0x03), Vendor OUI = 00:00:00, Type = 802.1X Auth
			# Знаю, по идиотски, но у мнее лень было придумываать
			if self.pkt[offset:offset+8] == b'\xaa\xaa\x03\x00\x00\x00\x88\x8e':
				eapol_pkt = self.pkt[offset +8:]
				eapol_version = eapol_pkt[0]
				eapol_type = eapol_pkt[1]
				eapol_length, = struct.unpack('>H', eapol_pkt[2:4])
				eapol_info = eapol_pkt[4:]
				#hex_str = ' '.join(format(x, '02x') for x in eapol_pkt)
				return {
					'version': eapol_version,
					'type': eapol_type,
					'length': eapol_length,
					'info': eapol_info
				}

		return None
		
	def return_EAPOL_Handshake(self):
		eapol = self.return_EAPOL_Data()
		if eapol:
			if eapol.get('type', None) == 3:
				eapol_info = eapol.get('info', None)
				if eapol_info:
					wpa_len = struct.unpack('>H', eapol_info[93:95])[0]
					return {
						'desc': eapol_info[0],
						'info': eapol_info[1:3],
						'length': struct.unpack('>H', eapol_info[3:5])[0],
						'replay_counter': struct.unpack('>Q', eapol_info[5:13])[0],
						'nonce': eapol_info[13:45],
						'iv': eapol_info[45:61],
						'rsc': eapol_info[61:69],
						'id': eapol_info[69:77],
						'mic': eapol_info[77:93],
						'wpa_len': wpa_len,
						'wpa_key': eapol_info[95:95+wpa_len] if wpa_len else None
					}
	
		return None
				
class PacketBuilder(IEEE80211_DEFS, IEEE80211_Utils):
	def __init__(self):
		pass
	
	def RadioTap_Channel(self, channel, flags=None):
		if flags:
			flags = self.makeFlagsField(self.ieee80211_radiotap_channel_flags_names, flags)
		else:
			flags = 0x0000;
		
		return int.from_bytes(struct.pack('<HH', channel, flags), 'little')

	def RadioTap(self, it_pad=0x00, it_presents=None):
		packet = bytearray()
		presents = bytearray()
		
		# RadioTap header - Version (0x00), Padding, Length, Presents (to many)
		packet.extend(struct.pack('<BB', 0x00, it_pad))
		_it_presents = 0x00000000
		
		if it_presents:
			offset = 8

			for present, _ in it_presents.items():
				present_index = self.getKeyByVal(self.ieee80211_radiotap_presents_names, present)
				if present_index:
					_it_presents |= (1 << present_index)

			for bit in range(16):
				if (_it_presents & (1 << bit)):
					present_chunk = bytearray()
					name = self.ieee80211_radiotap_presents_names.get(bit, None)
					value = it_presents.get(name)
					
					sa = self.ieee80211_radiotap_presents_sizes_aligns[bit]
					align = sa.get('align', 1)
					size = sa.get('size', 1)

					# Fucked stupid agliements blyatt
					if offset % align != 0:
						padding = align - (offset % align)
						present_chunk.extend(b'\x00' * padding)
						offset += padding
					# 1: 'b' if signed else 'B', 2: 'h' if signed else 'H', 4: 'i' if signed else 'I', 8: 'q' if signed else 'Q'
					fmt = self.get_struct_format(size, signed=value < 0)
					present_chunk.extend(struct.pack(f'<{fmt}', value))
					offset += size
					presents.extend(bytes(present_chunk))

		it_len = len(presents) + 8
		packet.extend(struct.pack('<H', it_len))
		packet.extend(struct.pack('<I', _it_presents))
		packet.extend(bytes(presents))

		return bytes(packet)


	def Dot11(self, fc, addr1, addr2=None, addr3=None, addr4=None, duration=0, frag=None, seq=None, fcflags=None, QoSControl=0x00, wep_iv=None, tkip_iv=None, ccmp_iv=None, ht_control=None):
		duration = (duration >> 1) & 0x7FFF
		packet = bytearray()
		flags = 0x00

		if fcflags:
			flags = self.makeFlagsField(self.ieee80211_fc_flags, fcflags)

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

		if fc in [0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8]:
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
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.extend(struct.pack('<Q', timestamp))
		packet.extend(struct.pack('<H', int(beacon_interval * 1000000 / 1024)))
		packet.extend(struct.pack('<H', _capabilities))
		
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
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.extend(struct.pack('<H', _capabilities))
		packet.extend(struct.pack('<H', status_code))
		packet.extend(struct.pack('<H', (assoc_id & 0x3FFF)))

		return bytes(packet)
	
	def Dot11ReassocReq(self, current_ap, capabilities=0x0000, listen_interval=0):
		packet = bytearray()
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.append(struct.pack('<H', _capabilities))
		packet.append(struct.pack('<H', listen_interval))
		packet.append(struct.pack('<H6s', self.mac2bin(current_ap)))

		return bytes(packet)
	
	def Dot11ReassocResp(self, capabilities=0x0000, status_code=0x0000, assoc_id=0x0000):
		packet = bytearray()
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.extend(struct.pack('<H', _capabilities))
		packet.extend(struct.pack('<H', status_code))
		packet.extend(struct.pack('<H', (assoc_id & 0x3FFF)))

		return bytes(packet)
		
	def Dot11ProbeReq(self):
		pass
	
	def Dot11ProbeResp(self, timestamp=0, beacon_interval=0x0000,  capabilities=None):
		packet = bytearray()
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.extend(struct.pack('<Q', timestamp))
		packet.extend(struct.pack('<H', beacon_interval))
		packet.extend(struct.pack('<H', _capabilities))
		
		return bytes(packet)

	def Dot11TLV16(self, id, info):
		packet = bytearray()
		packet.extend(struct.pack('>H', id))
		packet.extend(struct.pack('>H', len(info)))
		packet.extend(info)

		return bytes(packet)

	def Dot11TLV(self, id, info):
		packet = bytearray()
		packet.extend(struct.pack('<B', id))
		packet.extend(struct.pack('<B', len(info)))
		packet.extend(info)
	
		return bytes(packet)
		
	def LLC_SNAP(self, oui, control, code):
		packet = bytearray()
		packet.extend(b'\xAA\xAA') # LLC / DSAP, SSAP = SNAP
		packet.extend(struct.pack('>B', control)) # Fucking control, fucking understand 
		packet.extend(struct.pack('<3s', self.mac2bin(oui)))
		packet.extend(struct.pack('>H', code))

		return bytes(packet)
		
	def EAPOL(self, version, type, length):
		packet = bytearray()
		packet.extend(struct.pack('>B', version))
		packet.extend(struct.pack('>B', type))
		packet.extend(struct.pack('>H', length))

		return bytes(packet)
	
	def EAPOL_HandShake(self, key_desc, key_info, key_len, replay_counter, nonce, iv, rsc, id, mic, wpa_data=None):
		packet = bytearray()
		packet.extend(struct.pack('>B', key_desc))
		packet.extend(struct.pack('>H', key_info))
		packet.extend(struct.pack('>H', key_len))
		packet.extend(struct.pack('>Q', replay_counter))
		packet.extend(struct.pack('>32s', nonce))
		packet.extend(struct.pack('>16s', iv))
		packet.extend(struct.pack('>Q', rsc))
		packet.extend(struct.pack('>Q', id))
		packet.extend(struct.pack('>16s', mic))

		if wpa_data:
			wpa_len = len(wpa_data)
		else:
			wpa_len = 0
		packet.extend(struct.pack('>H', wpa_len))
		
		if wpa_data:
			packet.extend(wpa_data)

		return bytes(packet)
	
	def EAP(self, code, id, type, data):
		packet = bytearray()
		length = 5 + len(data)

		packet.extend(struct.pack('>B', code))
		packet.extend(struct.pack('>B', id))
		packet.extend(struct.pack('>H', length))
		packet.extend(struct.pack('>B', type))
		packet.extend(data)

		return bytes(packet)
	
	def EAP_EXPANDED(self, vendor_id, vendor_type, opcode, flags=0x00):
		packet = bytearray()
		packet.extend(struct.pack('>3s', self.mac2bin(vendor_id)))
		packet.extend(struct.pack('>I', vendor_type))
		packet.extend(struct.pack('>B', opcode))
		packet.extend(struct.pack('>B', flags))

		return bytes(packet)
		
