// Aleksander Postelga xposte00

#include "print_dns.h"

// Function to format timestamp
void format_time(const struct timeval *ts, char *buffer, size_t buf_size) {
    struct tm tm_info;
    time_t sec = ts->tv_sec;
    localtime_r(&sec, &tm_info);
    strftime(buffer, buf_size, "%Y-%m-%d %H:%M:%S", &tm_info);
}

// helper function to print verbose information
void print_verbose_info(char *time_str, const char *src_ip, const char *dst_ip,
                        const struct udphdr *udp_hdr, const u_char *dns_payload, char qr,
                        DnsHeader *dns_header, DnsMonitorContext *context) {
    printf("Timestamp: %s\n", time_str);
    printf("SrcIP: %s\n", src_ip);
    printf("DstIP: %s\n", dst_ip);
    printf("SrcPort: UDP/%d\n", ntohs(udp_hdr->uh_sport));
    printf("DstPort: UDP/%d\n", ntohs(udp_hdr->uh_dport));
    printf("Identifier: 0x%X\n", dns_header->id);

    int is_response = (qr == 'R');

    /*
     * The bitwise AND operation (&) is used to isolate specific bits before shifting.
     * Shifting is done to move the desired bits to the
     * least significant position for their interpretation.
     */
    printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
           is_response, (dns_header->flags & 0x7800) >> 11, (dns_header->flags & 0x0400) >> 10,
           (dns_header->flags & 0x0200) >> 9, (dns_header->flags & 0x0100) >> 8, (dns_header->flags & 0x0080) >> 7,
           (dns_header->flags & 0x0020) >> 5, (dns_header->flags & 0x0010) >> 4, dns_header->flags & 0x000F);

    printf("\n[Question Section]\n");
    const u_char *payload = dns_payload + 12;
    payload = process_question_section(payload, dns_payload, dns_header->question_count, context);
    if (!payload) {
        return;
    }

    if (dns_header->answer_count > 0) {
        payload = process_resource_record_section(payload, dns_payload, dns_header->answer_count, "Answer", context, is_response);
        if (!payload) {
            return;
        }
    }
    if (dns_header->authority_count > 0) {
        payload = process_resource_record_section(payload, dns_payload, dns_header->authority_count, "Authority", context, is_response);
        if (!payload) {
            return;
        }
    }
    if (dns_header->additional_count > 0) {
        payload = process_resource_record_section(payload, dns_payload, dns_header->additional_count, "Additional", context, is_response);
        if (!payload) {
            return;
        }
    }
    printf("====================\n");
}

// Helper function to print DNS information (IPv4 or IPv6)
void print_dns_info(const struct pcap_pkthdr *header, const char *src_ip, const char *dst_ip,
                    const struct udphdr *udp_hdr, const u_char *dns_payload, DnsMonitorContext *context) {
    // Time formatting
    char time_str[64];
    format_time(&header->ts, time_str, sizeof(time_str));

    // DNS header initialization
    DnsHeader dns_header;

    // Getting data from DNS header
    dns_header.id = ntohs(*(uint16_t *)(dns_payload));
    dns_header.flags = ntohs(*(uint16_t *)(dns_payload + 2));
    dns_header.question_count = ntohs(*(uint16_t *)(dns_payload + 4));
    dns_header.answer_count = ntohs(*(uint16_t *)(dns_payload + 6));
    dns_header.authority_count = ntohs(*(uint16_t *)(dns_payload + 8));
    dns_header.additional_count = ntohs(*(uint16_t *)(dns_payload + 10));

    // QR flag
    char qr = (dns_header.flags & 0x8000) ? 'R' : 'Q';

    // Process DNS packet to extract domains and translations
    int is_response = (qr == 'R');

    const u_char *payload = dns_payload + 12;

    if (!context->args->verbose) {
        // Process Question Section
        payload = process_question_section(payload, dns_payload, dns_header.question_count, context);
        if (!payload) {
            return;
        }

        // Process Answer Section
        if (dns_header.answer_count > 0) {
            payload = process_resource_record_section(payload, dns_payload, dns_header.answer_count, "Answer", context, is_response);
            if (!payload) {
                return;
            }
        }

        // Process Authority Section
        if (dns_header.authority_count > 0) {
            payload = process_resource_record_section(payload, dns_payload, dns_header.authority_count, "Authority", context, is_response);
            if (!payload) {
                return;
            }
        }

        // Process Additional Section
        if (dns_header.additional_count > 0) {
            payload = process_resource_record_section(payload, dns_payload, dns_header.additional_count, "Additional", context, is_response);
            if (!payload) {
                return;
            }
        }
        printf("%s %s -> %s (%c %d/%d/%d/%d)\n",
               time_str, src_ip, dst_ip, qr,
               dns_header.question_count, dns_header.answer_count,
               dns_header.authority_count, dns_header.additional_count);
    } else {
        // In verbose mode, print detailed information
        print_verbose_info(time_str, src_ip, dst_ip, udp_hdr, dns_payload, qr, &dns_header, context);
    }
}



// Function to print DNS information for IPv4 packets
void print_dns_information(const struct pcap_pkthdr *header, const struct ip *ip_hdr, const struct udphdr *udp_hdr,
                           const u_char *dns_payload, DnsMonitorContext *context) {
    // Format IP addresses
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    print_dns_info(header, src_ip, dst_ip, udp_hdr, dns_payload, context);
}

// Function to print DNS information for IPv6 packets
void print_dns_information_ipv6(const struct pcap_pkthdr *header, const struct ip6_hdr *ip6_hdr,
                                const struct udphdr *udp_hdr, const u_char *dns_payload, DnsMonitorContext *context) {
    // Format IP addresses
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

    print_dns_info(header, src_ip, dst_ip, udp_hdr, dns_payload, context);
}
