#include "radiotap.h"
#include <string.h>
#include <stdio.h>

int has_rt_header(const uint8_t *packet) {
	if (packet[0] == 0 && packet[1] == 0) {
		return 1;
	} else {
		return 0;
	}
}

int radiotap_parse(const uint8_t *packet, ieee80211_radiotap_data_t *data) {
	if (!packet || !data) return -1;
	if (!has_rt_header(packet)) return -1;
	
	memset(data, 0, sizeof(ieee80211_radiotap_data_t));
	data -> rt_header = (ieee80211_radiotap_header *)packet;
	
	unsigned char offset = 4;
	unsigned char ext_flag = 1;
	unsigned char presents_flags_cnt = 0;
	unsigned char flag_offset = 0;
	uint32_t presents_flags[8];
	
	while (ext_flag) {
		uint32_t it_present;
		memcpy(&it_present, packet + offset, sizeof(it_present));
		#ifdef __BIG_ENDIAN__
		it_present = le32toh(it_present);
		#endif
		ext_flag = (it_present >> 31) & 1UL;
		presents_flags[presents_flags_cnt++] = it_present;
		offset += 4;
	}
	
	for (unsigned char i = 0; i < presents_flags_cnt; i++) {
		uint32_t it_present = presents_flags[i];
		for (unsigned char bit = 0; bit < 32; bit++) {
			if ((it_present & (1UL << bit)) && bit <= 28) {
				offset = (offset + (ieee80211_radiotap_presents_align[bit] - 1)) & ~(ieee80211_radiotap_presents_align[bit] - 1);

				switch (bit) {
					case IEEE80211_RADIOTAP_Rate:
						uint8_t rate;
						memcpy(&rate, packet + offset, sizeof(rate));
						#ifdef __BIG_ENDIAN__
						rate = le8toh(rate);
						#endif
						data -> rate = (double)(rate / 2);
						break;
					case IEEE80211_RADIOTAP_Flags:
						uint8_t rt_flags;
						memcpy(&rt_flags, packet + offset, sizeof(rt_flags));
						#ifdef __BIG_ENDIAN__
						rt_flags = le8toh(rt_flags);
						#endif
						data -> flags.value = rt_flags;
						break;
					case IEEE80211_RADIOTAP_Antenna:
						uint8_t Antenna;
						memcpy(&Antenna, packet + offset, sizeof(Antenna));
						#ifdef __BIG_ENDIAN__
						dbm_Antenna_Signal = le8toh(Antenna);
						#endif
						break;
					case IEEE80211_RADIOTAP_dbm_Antenna_Signal:
						int8_t dbm_Antenna_Signal;
						memcpy(&dbm_Antenna_Signal, packet + offset, sizeof(dbm_Antenna_Signal));
						#ifdef __BIG_ENDIAN__
						dbm_Antenna_Signal = le8toh(dbm_Antenna_Signal);
						#endif
						data -> dbm_Antenna_Signal = dbm_Antenna_Signal;
						break;
					case IEEE80211_RADIOTAP_TSFT:
						uint64_t tsft;
						memcpy(&tsft, packet + offset, sizeof(tsft));
						#ifdef __BIG_ENDIAN__
						tsft = le64toh(tsft);
						#endif
						data -> tsft = tsft;
						break;
					case IEEE80211_RADIOTAP_Channel:
						uint32_t channel_info;
						memcpy(&channel_info, packet + offset, sizeof(channel_info));
						#ifdef __BIG_ENDIAN__
						channel_info = le32toh(channel_info);
						#endif
						uint16_t channel_frequency = (channel_info & 0xFFFF);						
						data -> channel_flags.value = (channel_info >> 16) & 0xFFFF;
						data -> channel_frequency = channel_frequency;
						data -> channel = ieee80211_radiotap_channels_2GHz[channel_frequency];
						break;
					case IEEE80211_RADIOTAP_TX_Flags:
						uint8_t tx_flags;
						memcpy(&tx_flags, packet + offset, sizeof(tx_flags));
						#ifdef __BIG_ENDIAN__
						tx_flags = le8toh(tx_flags);
						#endif
						data -> tx_flags.value = tx_flags;
						break;
					case IEEE80211_RADIOTAP_RX_Flags:
						uint8_t rx_flags;
						memcpy(&rx_flags, packet + offset, sizeof(rx_flags));
						#ifdef __BIG_ENDIAN__
						rx_flags = le8toh(rx_flags);
						#endif
						data -> rx_flags.value = rx_flags;
						break;
					case IEEE80211_RADIOTAP_MCS:
						uint8_t mcs[3];
						memcpy(mcs, packet + offset, sizeof(mcs));
						data -> mcs.known.value = mcs[0];
						data -> mcs.flags.value = mcs[1];
						data -> mcs.mcs_index = mcs[2];
						break;
				}
				offset += ieee80211_radiotap_presents_size[bit];
			}
		}
		
	}
	
	return 0;
}
