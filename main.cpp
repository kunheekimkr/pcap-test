// main.cpp

#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include"pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		libnet_ethernet_hdr*ethernet=(libnet_ethernet_hdr*)packet;
		libnet_ipv4_hdr*ipv4=(libnet_ipv4_hdr*)(ethernet+1); // add sizeof(libnet_ethernet_hdr)
		libnet_tcp_hdr*tcp=(libnet_tcp_hdr*)(ipv4+1); // add sizeof(libnet_ipv4_hdr)
		
		if(ntohs(ethernet->ether_type)==ETHERTYPE_IP && ipv4->ip_p ==IPPROTO_TCP){
			printMacAddr(ethernet);
			printf(", ");
			printIpTcp(ipv4, tcp);
			printData(packet,header->caplen-sizeof(libnet_ethernet_hdr)-sizeof(libnet_ipv4_hdr)-sizeof(libnet_tcp_hdr));
			printf("\n================================================================================\n");
		}

	}
	pcap_close(pcap);
}
