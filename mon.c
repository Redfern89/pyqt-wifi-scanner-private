#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

typedef struct {
	char source[18];
	char destination[18];
	char transmitter[18];
	uint16_t Duration;
	uint8_t control_field;
	uint8_t fragment;
	uint8_t sequence;
} Beacon;


uint16_t read_le16(const uint8_t *ptr) {
	return ptr[0] | (ptr[1] << 8);
}

void _32le_printf(uint32_t _32bit) {
	for (int i = 31; i >= 0; i--) {
		printf("%c", (_32bit & (1 << i)) ? '1' : '0');
	}
}

void _32be_printf(uint32_t _32bit) {
	for (int i = 0; i < 32; i++) {
		printf("%c", (_32bit & (1 << i)) ? '1' : '0');
	}
}

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

static inline uint32_t align_offset(uint32_t offset, uint32_t align) {
	return (offset + (align - 1)) & ~(align - 1);
}

void packet_handler__(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	ieee80211_radiotap_header *rt = (ieee80211_radiotap_header *)packet;
	uint32_t present_offset = 8; // Skip radiotap header
		
	//printf("Initial offset val = %d\n", present_offset);
	for (int i = 0; i < 32; i++) {
		if (rt -> it_present & (1UL << i)) {
			uint32_t present_size = 0;
			uint32_t present = 0x0000 | (1UL << i);
			present_size = ieee80211_radiotap_presents_size[present];
			present_offset = align_offset(present_offset, present_size);
			
			//printf("Present byte: %d, present size: %d, present offset: %d\n", i, present_size, present_offset);
			
			switch (present) {
				case IEEE80211_RADIOTAP_Channel:
					uint32_t channel_info = *(uint32_t *)(packet + present_offset - sizeof(uint32_t));
					uint8_t *channel_info_ptr = (uint8_t *)&channel_info;
					printf("offset: %d\n", present_offset);
					printf("channel_info: ");
					for (int j = 0; j < 4; j++) {
						printf("%02x ", channel_info_ptr[j]); 
					}
					printf("\n");
					
					break;
			}
			
			present_offset += present_size;
		}
	}
	
	printf("RadioTap Dump:\n");
	for (int j = 0; j < rt -> it_len; j++) {
		printf("%02x ", packet[j]);
		if ((j + 1) % 8 == 0) printf("   ");
		if ((j + 1) % 16 == 0) printf("\n");
	}
	
	exit(1);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	ieee80211_radiotap_header *rt = (ieee80211_radiotap_header *)packet;
	uint32_t present_offset = 8;
	
	printf("RadioTap presents: 0x%02x\n", rt -> it_present);
	
	//printf("Initial offset val = %d\n", present_offset);
	
	for (int i = 0; i < 32; i++) {
		uint32_t present_size = 0;
		if (rt -> it_present & (1UL << i)) {			
			uint32_t present = 0x0000 | (1UL << i);
			present_size = ieee80211_radiotap_presents_size[present];
			present_offset = align_offset(present_offset, present_size);
			
			//printf("Present byte: %d, present size: %d, present offset: %d\n", i, present_size, present_offset);
			
			switch (present) {
				case IEEE80211_RADIOTAP_Rate:
					uint8_t rate = *(uint8_t *)(packet + present_offset);
					printf("   Rate: %.1f mB/s\n", (double)(rate / 2));
					break;
				case IEEE80211_RADIOTAP_dbm_Antenna_Signal:
					int dbm_Antenna_signal = *(int8_t *)(packet + present_offset);
					printf("   Antenna signal: %d dbm\n", dbm_Antenna_signal);
					break;
				case IEEE80211_RADIOTAP_Channel:
					uint32_t channel_info = *(uint32_t *)(packet + present_offset - sizeof(uint32_t));
					uint8_t *channel_info_ptr = (uint8_t *)&channel_info;
					uint16_t channel_flags  = (channel_info_ptr[1] << 8) | channel_info_ptr[0];
					uint16_t channel_freq = (channel_info_ptr[3] << 8) | channel_info_ptr[2];
					
					uint8_t channel = 0;

					if (channel_freq >= 2412 && channel_freq <= 2484) {
						channel = ieee80211_radiotap_channels_2GHz[channel_freq]; 
					} else {
						printf("Present :: %s (%d), offset: %d, size: %d\n", ieee80211_radiotap_names[i], i, present_offset, present_size);
						printf("Channel freq (%d) out of range, RadioTap dump:\n", channel_freq);
						for (int j = 0; j < rt -> it_len; j++) {
							printf("%02x ", packet[j]);
							if ((j + 1) % 8 == 0) printf("   ");
							if ((j + 1) % 16 == 0) printf("\n");
						}
						exit(1);
					}
					
					printf("\t Flags: 0x%04x:\n", channel_flags);
					
					for (int j = 0; j < 16; j++) {
						if (channel_flags & (1U << j)) {
							printf("\t\t %s (%d)\n", ieee80211_radiotap_channel_flags_names[j], j);
						}
					}
					
					printf("   Channel frequency: %d (%d)\n", channel_freq, channel); 
					break;
				case IEEE80211_RADIOTAP_Antenna:
					present_offset = align_offset(present_offset, 1);
					uint8_t antenna = *(uint8_t *)(packet + present_offset);
					printf("Antenna: %d\n", antenna);
					break;
			}	
			//printf("Present :: %s (%d), offset: %d, size: %d\n", ieee80211_radiotap_names[i], i, present_offset, present_size);
		}
		present_offset += present_size;
		//printf("\n");
	}
	printf("\n");
}

// Функция обработки захваченных пакетов
void packet_handler_(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	// RadioTap Header
	if (packet[0] == 0x00 && packet[1] == 0x00) {
		int RadioTap_Len = packet[2];
		int BeaconFrame_Offset = RadioTap_Len;
		
		// Beacon frame
		if (packet[BeaconFrame_Offset] == 0x80 && packet[BeaconFrame_Offset +1] == 0x00) {
			Beacon *beacon = (Beacon *)user_data;
			
			snprintf(beacon -> destination, sizeof(beacon -> destination), "%02x:%02x:%02x:%02x:%02x:%02x", 
						packet[BeaconFrame_Offset +4], packet[BeaconFrame_Offset +5],
						packet[BeaconFrame_Offset +6], packet[BeaconFrame_Offset +7],
						packet[BeaconFrame_Offset +8], packet[BeaconFrame_Offset +9]
					);
			snprintf(beacon -> transmitter, sizeof(beacon -> transmitter), "%02x:%02x:%02x:%02x:%02x:%02x",
						packet[BeaconFrame_Offset +10], packet[BeaconFrame_Offset +11],
						packet[BeaconFrame_Offset +12], packet[BeaconFrame_Offset +13],
						packet[BeaconFrame_Offset +14], packet[BeaconFrame_Offset +15]
					);
			snprintf(beacon -> source, sizeof(beacon -> source), "%02x:%02x:%02x:%02x:%02x:%02x",
						packet[BeaconFrame_Offset +16], packet[BeaconFrame_Offset +17],
						packet[BeaconFrame_Offset +18], packet[BeaconFrame_Offset +19],
						packet[BeaconFrame_Offset +20], packet[BeaconFrame_Offset +21]
					);
			

			printf("\n\nDestination: %s \n", beacon -> destination);
			printf("Transmitter: %s \n", beacon -> transmitter);
			printf("Source: %s \n", beacon -> source);
			printf("OK\n");

			uint8_t tagged_params_offset = BeaconFrame_Offset + 36;
			if (packet[tagged_params_offset] == 0x00) {
				uint8_t ssid_length = packet[tagged_params_offset +1];
				char ssid[32];
				memcpy(ssid, &packet[tagged_params_offset+2], ssid_length);
				ssid[ssid_length] = '\0';
				printf("SSID: %s\n", ssid);
			}
				
			printf("Dump: \n");
			for (int i = BeaconFrame_Offset +36; i < pkthdr -> len; i++) {
				printf("%02x ", packet[i]);
				if ((i+1) % 16 == 0) printf("\n");
			}
		}
	}

}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "radio0mon"; // Интерфейс для прослушивания
	
    // Открываем интерфейс wlan0mon
    handle = pcap_open_live(dev, BUFSIZ, 1000, 1, errbuf);
    if (handle == NULL) {
        printf("Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    Beacon beacon;
    memset(&beacon, 0, sizeof(beacon));

    // Захватываем пакеты и обрабатываем их
    if (pcap_loop(handle, 0, packet_handler, (u_char *)&beacon) < 0) {
        printf("Error capturing packets: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_close(handle);
    return 0;
}
