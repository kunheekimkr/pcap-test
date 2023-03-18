//pcap-test.cpp
#include"pcap-test.h"

void printMacAddr(libnet_ethernet_hdr*ethernet){
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",ethernet->ether_shost[i]);
        if(i!=ETHER_ADDR_LEN-1)
            printf(":");
	}
	printf("->");
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",ethernet->ether_dhost[i]);
        if(i!=ETHER_ADDR_LEN-1)
            printf(":");
	}
}

void printIpTcp(libnet_ipv4_hdr*ipv4, libnet_tcp_hdr*tcp){
	for(int i=0;i< IP_ADDR_LEN;i++){
		printf("%d",ipv4->ip_src[i]);
        if(i!= IP_ADDR_LEN -1)
            printf(".");
        else
            printf(":%u",ntohs(tcp->th_sport));
	}
	printf("->");
	for(int i=0;i<IP_ADDR_LEN;i++){
		printf("%d",ipv4->ip_dst[i]);
        if(i!= IP_ADDR_LEN -1)
            printf(".");
        else
            printf(":%u\n",ntohs(tcp->th_dport));

	}
}

void printData(const u_char*packet,int size) {
	int startPoint = sizeof(libnet_ethernet_hdr)+ sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr);
	for(int i=0;i<10 &&i<size;i++){
		printf("%02x",packet[startPoint +i]);
		if((size <10 && i != size-1) || (size >=10 && i!=9))
			printf("|");
	}
}