// Aleksander Postelga xposte00

#ifndef DNS_MONITOR_PROCESS_DNS_PACKET_H
#define DNS_MONITOR_PROCESS_DNS_PACKET_H

#include "domains.h"
#include "translations.h"
#include "dns_structures.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pcap.h>

int process_domain_name(const u_char *packet_start, const u_char *payload, char *buffer, size_t buffer_size);
const u_char *process_resource_record_section(const u_char *payload, const u_char *packet_start, int record_count, const char *section_name, DnsMonitorContext *context, int is_response);
const u_char *process_question_section(const u_char *payload, const u_char *packet_start, int question_count, DnsMonitorContext *context);


#endif //DNS_MONITOR_PROCESS_DNS_PACKET_H