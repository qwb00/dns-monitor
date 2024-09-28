//
// Created by Aleksander on 26.09.2024.
//

#ifndef DNS_MONITOR_DNS_CAPTURE_H
#define DNS_MONITOR_DNS_CAPTURE_H

#include <pcap/pcap.h>
#include <netinet/ip.h>    // for struct ip
#include <netinet/udp.h>   // for struct udphdr
#include <arpa/inet.h>     // for inet_ntoa
#include <pcap/pcap.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include "args.h"

void dns_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void capture_dns_packets(ProgramArguments args);

#endif //DNS_MONITOR_DNS_CAPTURE_H
