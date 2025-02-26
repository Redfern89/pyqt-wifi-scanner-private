#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

const uint32_t ieee80211_radiotap_channels_2GHz[] = {
	[2412] = 1,
	[2417] = 2,
	[2422] = 3,
	[2427] = 4,
	[2432] = 5,
	[2437] = 6,
	[2442] = 7,
	[2447] = 8,
	[2452] = 9,
	[2457] = 10,
	[2462] = 11,
	[2467] = 12,
	[2472] = 13,
	[2484] = 14,
};

const char *ieee80211_radiotap_names[] = {
	[0] = "TSFT",
	[1] = "Flags",
	[2] = "Rate",
	[3] = "Channel",
	[4] = "FHSS",
	[5] = "dbm_Antenna_Signal",
	[6] = "dbm_Antenna_Noise",
	[7] = "Lock_Quality",
	[8] = "TX_Attenuation",
	[9] = "db_TX_Attenuation",
	[10] = "dbm_TX_Power",
	[11] = "Antenna",
	[12] = "db_Antenna_Signal",
	[13] = "db_Antenna_Noise",
	[14] = "RX_Flags",
	[15] = "TX_Flags",
	[16] = "RTS_retries",
	[17] = "Data_retries",
	[18] = "Channel_plus",
	[19] = "MCS",
	[20] = "A_MPDU_Status",
	[21] = "VHT_Info",
	[22] = "Frame_timestamp",
	[23] = "HE_Info",
	[24] = "HE_MU_Info",
	[25] = "RESERVED_1",
	[26] = "Null_Length_PSDU",
	[27] = "L_SIG",
	[28] = "TLVs",
	[29] = "RadioTap_NS_Next",
	[30] = "Vendor_NS_Next",
	[31] = "Ext"
};

typedef struct {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
}__attribute__((packed)) ieee80211_radiotap_header;

typedef enum {
	IEEE80211_RADIOTAP_TSFT                 = (1UL << 0),
	IEEE80211_RADIOTAP_Flags                = (1UL << 1),
	IEEE80211_RADIOTAP_Rate                 = (1UL << 2),
	IEEE80211_RADIOTAP_Channel              = (1UL << 3),
	IEEE80211_RADIOTAP_FHSS                 = (1UL << 4),
	IEEE80211_RADIOTAP_dbm_Antenna_Signal   = (1UL << 5),
	IEEE80211_RADIOTAP_dbm_Antenna_Noise    = (1UL << 6),
	IEEE80211_RADIOTAP_Lock_Quality         = (1UL << 7),
	IEEE80211_RADIOTAP_TX_Attenuation       = (1UL << 8),
	IEEE80211_RADIOTAP_db_TX_Attenuation    = (1UL << 9),
	IEEE80211_RADIOTAP_dbm_TX_Power         = (1UL << 10),
	IEEE80211_RADIOTAP_Antenna              = (1UL << 11),
	IEEE80211_RADIOTAP_db_Antenna_Signal    = (1UL << 12),
	IEEE80211_RADIOTAP_db_Antenna_Noise     = (1UL << 13),
	IEEE80211_RADIOTAP_RX_Flags             = (1UL << 14),
	IEEE80211_RADIOTAP_TX_Flags             = (1UL << 15),
	IEEE80211_RADIOTAP_RTS_retries			= (1UL << 16),
	IEEE80211_RADIOTAP_Data_retries         = (1UL << 17),
	IEEE80211_RADIOTAP_Channel_plus         = (1UL << 18),
	IEEE80211_RADIOTAP_MCS                  = (1UL << 19),
	IEEE80211_RADIOTAP_A_MPDU_Status        = (1UL << 20),
	IEEE80211_RADIOTAP_VHT_Info             = (1UL << 21),
	IEEE80211_RADIOTAP_Frame_timestamp      = (1UL << 22),
	IEEE80211_RADIOTAP_HE_Info              = (1UL << 23),
	IEEE80211_RADIOTAP_HE_MU_Info           = (1UL << 24),
	IEEE80211_RADIOTAP_RESERVED_1           = (1UL << 25), // Зарезервировано
	IEEE80211_RADIOTAP_NUL_Length_PSDU      = (1UL << 26),
	IEEE80211_RADIOTAP_L_SIG                = (1UL << 27),
	IEEE80211_RADIOTAP_TLVs                 = (1UL << 28),
	IEEE80211_RADIOTAP_RadioTap_NS_Next     = (1UL << 29),
	IEEE80211_RADIOTAP_Vendor_NS_Next       = (1UL << 30),
	IEEE80211_RADIOTAP_Ext                  = (1UL << 31)
} ieee80211_radiotap_present_flags_t;

/*typedef enum
	
} ieee80211_radiotap_presents_size;
*/

static const unsigned char ieee80211_radiotap_presents_size[] = {
	[IEEE80211_RADIOTAP_TSFT]				= 8,
	[IEEE80211_RADIOTAP_Flags]				= 1,
	[IEEE80211_RADIOTAP_Rate]				= 1,
	[IEEE80211_RADIOTAP_Channel]			= 2+2,
	[IEEE80211_RADIOTAP_FHSS]				= 2,
	[IEEE80211_RADIOTAP_dbm_Antenna_Signal] = 1,
	[IEEE80211_RADIOTAP_dbm_Antenna_Noise]	= 1,
	[IEEE80211_RADIOTAP_Lock_Quality]		= 2,
	[IEEE80211_RADIOTAP_TX_Attenuation]		= 2,
	[IEEE80211_RADIOTAP_db_TX_Attenuation]	= 2,
	[IEEE80211_RADIOTAP_dbm_TX_Power]		= 1,
	[IEEE80211_RADIOTAP_Antenna]			= 1,
	[IEEE80211_RADIOTAP_db_Antenna_Signal]	= 1,
	[IEEE80211_RADIOTAP_db_Antenna_Noise]	= 1,
	[IEEE80211_RADIOTAP_RX_Flags]			= 2,
	[IEEE80211_RADIOTAP_TX_Flags]			= 2,
	[IEEE80211_RADIOTAP_RTS_retries]		= 1,
	[IEEE80211_RADIOTAP_Data_retries]		= 1,
	[IEEE80211_RADIOTAP_MCS]				= 3,
	[IEEE80211_RADIOTAP_A_MPDU_Status]		= 8,
	[IEEE80211_RADIOTAP_VHT_Info]			= 12,
	[IEEE80211_RADIOTAP_Frame_timestamp]	= 12
};

static const unsigned char ieee80211_radiotap_presents_align[] = {
	[IEEE80211_RADIOTAP_TSFT]				= 8,
	[IEEE80211_RADIOTAP_Flags]				= 1,
	[IEEE80211_RADIOTAP_Rate]				= 1,
	[IEEE80211_RADIOTAP_Channel]			= 2,
	[IEEE80211_RADIOTAP_FHSS]				= 2,
	[IEEE80211_RADIOTAP_dbm_Antenna_Signal] = 1,
	[IEEE80211_RADIOTAP_dbm_Antenna_Noise]	= 1,
	[IEEE80211_RADIOTAP_Lock_Quality]		= 2,
	[IEEE80211_RADIOTAP_TX_Attenuation]		= 2,
	[IEEE80211_RADIOTAP_db_TX_Attenuation]	= 2,
	[IEEE80211_RADIOTAP_dbm_TX_Power]		= 1,
	[IEEE80211_RADIOTAP_Antenna]			= 1,
	[IEEE80211_RADIOTAP_db_Antenna_Signal]	= 1,
	[IEEE80211_RADIOTAP_db_Antenna_Noise]	= 1,
	[IEEE80211_RADIOTAP_RX_Flags]			= 2,
	[IEEE80211_RADIOTAP_TX_Flags]			= 2,
	[IEEE80211_RADIOTAP_RTS_retries]		= 1,
	[IEEE80211_RADIOTAP_Data_retries]		= 1,
	[IEEE80211_RADIOTAP_MCS]				= 1,
	[IEEE80211_RADIOTAP_A_MPDU_Status]		= 4,
	[IEEE80211_RADIOTAP_VHT_Info]			= 2,
	[IEEE80211_RADIOTAP_Frame_timestamp]	= 8
};

typedef enum {
	CFP										= (1 << 0),
	Preamble								= (1 << 1),
	WEP										= (1 << 2),
	Fragmentation							= (1 << 3),
	FCS_at_END								= (1 << 4),
	Data_Pad								= (1 << 5),
	Bad_FCS									= (1 << 6),
	Short_GI								= (1 << 7)
} ieee80211_radiotap_flags_t;

typedef enum {
	MHz_700									= (1 << 0),
	MHz_800									= (1 << 1),
	Mhz_900									= (1 << 2),
	Turbo									= (1 << 4),
	CCK										= (1 << 5),
	OFDM									= (1 << 6),
	GHz_2									= (1 << 7),
	GHz_5									= (1 << 8),
	Passive									= (1 << 9),
	Dynamic_CCK_OFDM						= (1 << 10),
	GFSK									= (1 << 11),
	GSM										= (1 << 12),
	Static_turbo							= (1 << 13),
	Half_rate_channel_10Mhz					= (1 << 14),
	Quarter_rate_channel_5Mhz				= (1 << 15)
} ieee80211_radiotap_channel_flags_t;

const char *ieee80211_radiotap_channel_flags_names[] = {
	[0] = "700 MHz",
	[1] = "800 MHz",
	[2] = "900 MHz",
	[4] = "Turbo",
	[5] = "CCK",
	[6] = "OFDM",
	[7] = "2 GHz",
	[8] = "5 GHz",
	[9] = "Passive",
	[10] = "Dynamic CCK-OFDM",
	[11] = "GFSK",
	[12] = "GSM",
	[13] = "Static turbo",
	[14] = "Half-Rate channel 10 MHz",
	[15] = "Quarter-Rate channel 5 MHz"
};

typedef struct {
	uint64_t tsft;
	ieee80211_radiotap_flags_t flags;
	double rate;
	uint16_t channel_freq;
	ieee80211_radiotap_channel_flags_t channel_flags;
	int8_t dbm_antenna_signal;
	int8_t dbm_antenna_noise;
	uint16_t lock_quality;
	uint16_t tx_attenuation;
	uint16_t db_tx_attenuation;
	int8_t dbm_tx_power;
	uint8_t antenna;
	int8_t db_antenna_signal;
	int8_t db_antenna_noise;
	uint16_t rx_flags;
	uint16_t tx_flags;
	uint8_t data_retries;
	uint32_t frame_timestamp;	
} ieee80211_radiotap_data_t;

static uint32_t ieee80211_radiotap_get_present_offset(uint32_t flagsPtr, uint32_t flagsCnt, uint32_t start) {
	unsigned char offset = 0;
	for (unsigned char i = 0; i < flagsCnt; i++) {
		if (flagsPtr & (1U << i)) {
			offset += offset & (ieee80211_radiotap_presents_align[i] -1);
			offset += ieee80211_radiotap_presents_size[i];
		}
	}
	return offset;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	ieee80211_radiotap_header *rt = (ieee80211_radiotap_header *)packet;
	uint32_t present_offset = 8;
	
	uint32_t offset = ieee80211_radiotap_get_present_offset(rt -> it_present, 32, present_offset);
	
	printf("offset: %d\n", offset);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "radio0mon";
    
    handle = pcap_open_live(dev, BUFSIZ, 1000, 1, errbuf);
    if (handle == NULL) {
		printf("Error opening device %s: %s\n", dev, errbuf);
		return 1;
	}
	
	if (pcap_loop(handle, 0, packet_handler, NULL)) {
		printf("Error capturing packets: %s\n", pcap_geterr(handle));
		return 1;
	}
	
	pcap_close(handle);
	return 1;
	
}
