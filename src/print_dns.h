// Aleksander Postelga xposte00

#ifndef DNS_MONITOR_PRINT_DNS_H
#define DNS_MONITOR_PRINT_DNS_H

#include "dns_structures.h"
#include "process_dns_packet.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <time.h>


void print_dns_information_ipv6(const struct pcap_pkthdr *header, const struct ip6_hdr *ip6_hdr, const struct udphdr *udp_hdr, const u_char *dns_payload, DnsMonitorContext *context);
void print_dns_information(const struct pcap_pkthdr *header, const struct ip *ip_hdr, const struct udphdr *udp_hdr, const u_char *dns_payload, DnsMonitorContext *context);

#endif //DNS_MONITOR_PRINT_DNS_H