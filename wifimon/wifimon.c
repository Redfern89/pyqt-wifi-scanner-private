#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "radiotap/radiotap.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	ieee80211_radiotap_data_t data;
	if (radiotap_parse(packet, &data) == 0) {
		printf("RadioTap header Len: %d\n", data.rt_header -> it_len);\
		printf("Flags: 0x%02x\n", data.flags);
		
		for (int i = 0; i < 8; i++) {
			if (data.flags.value & (1U << i)) {
				printf(" Flag: %s\n", ieee80211_radiotap_flags_names[i]);
			}
		}
		printf("dbm_Antenna_Signal: %d dBm\n", data.dbm_Antenna_Signal);
		
		printf("Channel: %d [%d]\n", data.channel, data.channel_frequency);
		for (int i = 0; i < 16; i++) {
			if (data.channel_flags.value & (1U << i)) {
				printf(" Flag: %s\n", ieee80211_radiotap_channel_flags_names[i]);
			}
		}
		
		printf("Rate: %.1f mB/s\n", data.rate);
		printf("\n");
	} else {
		
	}
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "radio0mon";
    
    handle = pcap_open_live(dev, BUFSIZ, 1000, 1, errbuf);
	//handle = pcap_open_offline("test.pcapng", errbuf);
    if (handle == NULL) {
		printf("Error opening device %s\n", errbuf);
		return 1;
	}
	
	if (pcap_loop(handle, 0, packet_handler, NULL)) {
		printf("Error capturing packets: %s\n", pcap_geterr(handle));
		return 1;
	}
	
	pcap_close(handle);
	return 1;
	
}
