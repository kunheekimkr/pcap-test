//pcap-test.h
#pragma once

#include<stdio.h>
#include<netinet/in.h>
#include"libnet.h"

void printMacAddr(libnet_ethernet_hdr*ethernet);
void printIpTcp(libnet_ipv4_hdr*ipv4, libnet_tcp_hdr*tcp);
void printData(const u_char*packet,int size);
