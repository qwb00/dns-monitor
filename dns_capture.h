// dns_capture.h

#ifndef DNS_MONITOR_DNS_CAPTURE_H
#define DNS_MONITOR_DNS_CAPTURE_H

#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <signal.h>
#include <resolv.h>

#include "domains.h"
#include "translations.h"
#include "process_dns_packet.h"
#include "print_dns.h"

void dns_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void capture_dns_packets(DnsMonitorContext *context);
void handle_signal(int signal);
void free_all_resources(DnsMonitorContext *context);

#endif //DNS_MONITOR_DNS_CAPTURE_H
