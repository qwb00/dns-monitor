//
// Created by Aleksander on 10.11.2024.
//

#include "process_dns_packet.h"

// Function to get DNS type name from type code
const char *get_dns_type_name(uint16_t type) {
    switch(type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 15: return "MX";
        case 28: return "AAAA";
        case 33: return "SRV";
        default: return "OTHER";
    }
}

// Function to get DNS class name from class code
const char *get_dns_class_name(uint16_t class) {
    switch(class) {
        case 1: return "IN";   // Internet
        case 3: return "CH";   // Chaos
        case 4: return "HS";   // Hesiod
        default: return "UNKNOWN";
    }
}

int process_domain_name(const u_char *packet_start, const u_char *payload, char *buffer, size_t buffer_size) {
    int name_len = dn_expand(packet_start, packet_start + 512, payload, buffer, buffer_size);
    if (name_len < 0) {
        fprintf(stderr, "Error: Unable to expand domain name.\n");
        return -1;
    }
    return name_len;
}

void process_a_record(const u_char *payload, char *domain_name, uint16_t rdlength, DnsMonitorContext *context, int is_response) {
    if (rdlength == 4) {
        struct in_addr addr;
        memcpy(&addr, payload, rdlength);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        printf("%s\n", ip_str);

        if (context->args->translations_file && is_response) {
            add_translation(&context->translation_set, domain_name, ip_str, context->args->translations_file);
        }
    }
}

void process_aaaa_record(const u_char *payload, char *domain_name, uint16_t rdlength, DnsMonitorContext *context, int is_response) {
    if (rdlength == 16) {
        struct in6_addr addr6;
        memcpy(&addr6, payload, rdlength);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr6, ip_str, sizeof(ip_str));
        printf("%s\n", ip_str);

        if (context->args->translations_file && is_response) {
            add_translation(&context->translation_set, domain_name, ip_str, context->args->translations_file);
        }
    }
}

void process_ns_cname_record(const u_char *packet_start, const u_char *payload, DnsMonitorContext *context) {
    char rdata_domain[256];
    int name_len = process_domain_name(packet_start, payload, rdata_domain, sizeof(rdata_domain));
    if (name_len >= 0) {
        printf("%s.\n", rdata_domain);
        if (context->args->domains_file) {
            add_domain(&context->domain_set, rdata_domain, context->args->domains_file);
        }
    }
}

void process_mx_record(const u_char *packet_start, const u_char *payload, DnsMonitorContext *context) {
    uint16_t preference = ntohs(*(uint16_t *) payload);
    char rdata_domain[256];
    int name_len = process_domain_name(packet_start, payload + 2, rdata_domain, sizeof(rdata_domain));
    if (name_len >= 0) {
        printf("%d %s.\n", preference, rdata_domain);
        if (context->args->domains_file) {
            add_domain(&context->domain_set, rdata_domain, context->args->domains_file);
        }
    }
}

void process_soa_record(const u_char *packet_start, const u_char *payload, uint16_t rdlength) {
    char mname[256], rname[256];
    const u_char *rdata_ptr = payload;
    int mname_len = process_domain_name(packet_start, rdata_ptr, mname, sizeof(mname));
    if (mname_len < 0) return;
    rdata_ptr += mname_len;

    int rname_len = process_domain_name(packet_start, rdata_ptr, rname, sizeof(rname));
    if (rname_len < 0) return;
    rdata_ptr += rname_len;

    if (rdata_ptr + 20 > payload + rdlength) return;

    uint32_t serial = ntohl(*(uint32_t *) rdata_ptr); rdata_ptr += 4;
    uint32_t refresh = ntohl(*(uint32_t *) rdata_ptr); rdata_ptr += 4;
    uint32_t retry = ntohl(*(uint32_t *) rdata_ptr); rdata_ptr += 4;
    uint32_t expire = ntohl(*(uint32_t *) rdata_ptr); rdata_ptr += 4;
    uint32_t minimum = ntohl(*(uint32_t *) rdata_ptr);

    printf("%s. %s. (\n\t%u ; Serial\n\t%u ; Refresh\n\t%u ; Retry\n\t%u ; Expire\n\t%u ; Minimum TTL\n)\n",
           mname, rname, serial, refresh, retry, expire, minimum);
}

void process_srv_record(const u_char *packet_start, const u_char *payload, DnsMonitorContext *context) {
    uint16_t priority = ntohs(*(uint16_t *) payload);
    uint16_t weight = ntohs(*(uint16_t *) (payload + 2));
    uint16_t port = ntohs(*(uint16_t *) (payload + 4));
    char domain[256];
    int name_len = process_domain_name(packet_start, payload + 6, domain, sizeof(domain));

    if (name_len >= 0) {
        printf("%u %u %u %s.\n", priority, weight, port, domain);
        if (context->args->domains_file) {
            add_domain(&context->domain_set, domain, context->args->domains_file);
        }
    }
}


const u_char *process_resource_record_section(const u_char *payload, const u_char *packet_start, int record_count, const char *section_name, DnsMonitorContext *context, int is_response) {
    char domain_name[256];
    printf("\n[%s Section]\n", section_name);
    for (int i = 0; i < record_count; i++) {
        int name_len = process_domain_name(packet_start, payload, domain_name, sizeof(domain_name));
        if (name_len < 0) return NULL;
        payload += name_len;

        uint16_t rtype = ntohs(*(uint16_t *) payload);
        uint16_t rclass = ntohs(*(uint16_t *) (payload + 2));
        uint32_t ttl = ntohl(*(uint32_t *) (payload + 4));
        uint16_t rdlength = ntohs(*(uint16_t *) (payload + 8));
        payload += 10;

        printf("%s. %u %s %s ", domain_name, ttl, get_dns_class_name(rclass), get_dns_type_name(rtype));

        if (context->args->domains_file) {
            add_domain(&context->domain_set, domain_name, context->args->domains_file);
        }

        if (payload + rdlength > packet_start + 512) return NULL;

        switch (rtype) {
            case 1:  // A record
                process_a_record(payload, domain_name, rdlength, context, is_response);
                break;
            case 28: // AAAA record
                process_aaaa_record(payload, domain_name, rdlength, context, is_response);
                break;
            case 2:  // NS record
            case 5:  // CNAME record
                process_ns_cname_record(packet_start, payload, context);
                break;
            case 15: // MX record
                process_mx_record(packet_start, payload, context);
                break;
            case 6:  // SOA record
                process_soa_record(packet_start, payload, rdlength);
                break;
            case 33: // SRV record
                process_srv_record(packet_start, payload, context);
                break;
            default:
                printf("(other data, length %d)\n", rdlength);
                break;
        }

        payload += rdlength;
    }
    return payload;
}

// Function to process the Question Section
const u_char *process_question_section(const u_char *payload, const u_char *packet_start, int question_count, DnsMonitorContext *context) {
    char domain_name[256];
    for (int i = 0; i < question_count; i++) {
        // Read domain name
        int name_len = process_domain_name(packet_start, payload, domain_name, sizeof(domain_name));
        if (name_len < 0) return NULL;
        payload += name_len;

        // Read type and class
        uint16_t qtype = ntohs(*(uint16_t*) payload);
        uint16_t qclass = ntohs(*(uint16_t*) (payload + 2));
        payload += 4;

        // Print question
        printf("%s. %s %s\n", domain_name, get_dns_class_name(qclass), get_dns_type_name(qtype));

        // If domainsfile is specified, add domain name
        if (context->args->domains_file) {
            add_domain(&context->domain_set, domain_name, context->args->domains_file);
        }
    }
    return payload;
}
