#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

// Структура для хранения информации о точках доступа
typedef struct {
    char ssid[32];
    char bssid[18];
} APInfo;

typedef struct {
	char source[18];
	char destination[18];
	char transmitter[18];
	uint16_t Duration;
	uint8_t control_field;
	uint8_t fragment;
	uint8_t sequence;
} Beacon;

// Функция обработки захваченных пакетов
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	
	// RadioTap Header
	if (packet[0] == 0x00 && packet[1] == 0x00 && packet[2] == 0x12) {
		//printf("Captured packet of length %d\n", pkthdr->len);
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
			
			//if (strcmp(beacon -> transmitter, "04:5e:a4:6a:28:47") == 0) {
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
				
			//}
			
			printf("\n");
		}
		
		//printf("\n\n");
	}
	
   /* // Печатаем каждый захваченный пакет в HEX, чтобы понять, что вообще приходит
    printf("Captured packet of length %d\n", pkthdr->len);
    for (int i = 0; i < pkthdr->len; i++) {
        printf("%02x ", packet[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Стандартная обработка, если это 802.11 Beacon фрейм
    if (packet[0] == 0x80) {  // Тип фрейма Beacon - это 0x80
        APInfo *ap = (APInfo *)user_data;
        //printf("dd");

        // Копируем BSSID из источника
        snprintf(ap->bssid, sizeof(ap->bssid), "%02x:%02x:%02x:%02x:%02x:%02x",
            packet[10], packet[11], packet[12], packet[13], packet[14], packet[15]);

        // Извлекаем SSID (после заголовков, на 37-ом байте и дальше)
        int ssid_length = packet[37];
        memcpy(ap->ssid, &packet[38], ssid_length);
        ap->ssid[ssid_length] = '\0'; // Завершаем строку

        printf("Found AP: BSSID: %s, SSID: %s\n", ap->bssid, ap->ssid);
    }
    * */
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "wlan0mon"; // Интерфейс для прослушивания

    // Открываем интерфейс wlan0mon
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    // Добавим фильтрацию, чтобы ловить только 802.11 пакеты
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "wlan type mgt", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    APInfo ap_info;
    memset(&ap_info, 0, sizeof(ap_info));

    // Захватываем пакеты и обрабатываем их
    if (pcap_loop(handle, 0, packet_handler, (u_char *)&ap_info) < 0) {
        printf("Error capturing packets: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_close(handle);
    return 0;
}
