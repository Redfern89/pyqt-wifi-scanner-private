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

typedef struct {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
}__attribute__((packed)) ieee80211_radiotap_header;

typedef struct {
	uint8_t TSFT;
	uint8_t Flags;
	uint8_t Rate;
	uint8_t Channel;
	uint8_t FHSS;
	uint8_t dbm_Antenna_Signal;
	uint8_t dbm_Antenna_Noise;
	uint8_t Lock_Quality;
	uint8_t TX_Attenuation;
	uint8_t db_TX_Attenuation;
	uint8_t dbm_TX_Power;
	uint8_t db_Antenna_Signal;
	uint8_t db_Antenna_Noise;
	uint8_t RX_Flags;
	uint8_t TX_Flags;
	uint8_t Data_retries;
	uint8_t MCS;
	uint8_t A_MPDU_Status;
	uint8_t VHT_Info;
	uint8_t Frame_timestamp;
	uint8_t HE_Info;
	uint8_t HE_MU_Info;
	uint8_t Null_Length_PSDU;
	uint8_t L_SIG;
	uint8_t TLVs;
	uint8_t RadioTap_NS_Next;
	uint8_t Vendor_NS_Next;
	uint8_t Ext;
}__attribute__((packed)) ieee80211_radiotap_present_flags;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	ieee80211_radiotap_header *rt = (ieee80211_radiotap_header *)packet;
	ieee80211_radiotap_present_flags *rt_present = (ieee80211_radiotap_present_flags *)rt -> it_present;
	
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
    char *dev = "wlan0mon"; // Интерфейс для прослушивания

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
