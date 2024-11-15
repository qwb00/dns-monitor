// Aleksander Postelga xposte00

#ifndef DNS_MONITOR_DNS_STRUCTURES_H
#define DNS_MONITOR_DNS_STRUCTURES_H

#include "args.h"
#include "domains.h"
#include "translations.h"
#include "pcap/pcap.h"

typedef struct {
    ProgramArguments *args;
    DomainSet domain_set;
    TranslationSet translation_set;
    pcap_t *pcap_handle;
} DnsMonitorContext;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
} DnsHeader;

#endif //DNS_MONITOR_DNS_STRUCTURES_H
