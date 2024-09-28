//
// Created by Aleksander on 26.09.2024.
//

#include "dns_capture.h"

const u_char *read_dns_name(const u_char *payload, const u_char *packet_start, char *buffer, size_t buffer_size) {
    int len = *payload;
    size_t pos = 0;
    while (len > 0) {
        if ((len & 0xC0) == 0xC0) {
            // pointer to another part of the packet
            int offset = ((len & 0x3F) << 8) | *(payload + 1);
            read_dns_name(packet_start + offset, packet_start, buffer + pos, buffer_size - pos);
            return payload + 2;
        } else {
            if (pos + len + 1 >= buffer_size) {
                // buffer overflow
                break;
            }
            strncpy(buffer + pos, (const char *)(payload + 1), len);
            pos += len;
            buffer[pos++] = '.';
            payload += len + 1;
            len = *payload;
        }
    }
    buffer[pos ? pos - 1 : 0] = '\0';  // delete last dot
    return payload + 1;
}

const u_char *process_question_section(const u_char *payload, const u_char *packet_start, int question_count) {
    char domain_name[256];
    for (int i = 0; i < question_count; i++) {
        // read domain name
        payload = read_dns_name(payload, packet_start, domain_name, sizeof(domain_name));

        // read type and class
        unsigned short qtype = (payload[0] << 8) | payload[1];
        unsigned short qclass = (payload[2] << 8) | payload[3];
        payload += 4;

        // print question
        printf("%s. %s %s\n", domain_name, (qclass == 1 ? "IN" : "?"), (qtype == 1 ? "A" : qtype == 28 ? "AAAA" : "OTHER"));
    }
    return payload;
}

const u_char *process_resource_record_section(const u_char *payload, const u_char *packet_start, int record_count, const char *section_name) {
    char domain_name[256];
    printf("\n[%s Section]\n", section_name);
    for (int i = 0; i < record_count; i++) {
        // Read domain name
        payload = read_dns_name(payload, packet_start, domain_name, sizeof(domain_name));

        // Read type, class, TTL, RDLength
        unsigned short rtype = (payload[0] << 8) | payload[1];
        unsigned short rclass = (payload[2] << 8) | payload[3];
        unsigned int ttl = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7];
        unsigned short rdlength = (payload[8] << 8) | payload[9];
        payload += 10;

        printf("%s. %s %s %u ", domain_name, (rclass == 1 ? "IN" : "?"), (rtype == 1 ? "A" : rtype == 28 ? "AAAA" : "OTHER"), ttl);

        // A (IPv4) address
        if (rtype == 1 && rdlength == 4) {
            struct in_addr addr;
            memcpy(&addr, payload, 4);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            printf("%s\n", ip_str);
        }
            // AAAA (IPv6) address
        else if (rtype == 28 && rdlength == 16) {
            struct in6_addr addr6;
            memcpy(&addr6, payload, 16);
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr6, ip_str, sizeof(ip_str));
            printf("%s\n", ip_str);
        }
            // skip other types
        else {
            printf("(other data, length %d)\n", rdlength);
        }

        // next record
        payload += rdlength;
    }
    return payload;
}

void format_time(const struct timeval *ts, char *buffer, size_t buf_size) {
    struct tm *tm_info;
    time_t sec = ts->tv_sec;
    tm_info = localtime(&sec);
    strftime(buffer, buf_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

void print_dns_information(const struct pcap_pkthdr *header, const struct ip *ip_hdr, const struct udphdr *udp_hdr, const u_char *dns_payload, ProgramArguments *args) {
    // format IP addresses
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // format time
    char time_str[64];
    format_time(&header->ts, time_str, sizeof(time_str));

    // Getting ID and flags
    unsigned short dns_id = (dns_payload[0] << 8) | dns_payload[1];
    unsigned short dns_flags = (dns_payload[2] << 8) | dns_payload[3];

    // Getting counts
    unsigned short question_count = (dns_payload[4] << 8) | dns_payload[5];
    unsigned short answer_count = (dns_payload[6] << 8) | dns_payload[7];
    unsigned short authority_count = (dns_payload[8] << 8) | dns_payload[9];
    unsigned short additional_count = (dns_payload[10] << 8) | dns_payload[11];

    // response or query
    char qr = (dns_flags & 0x8000) ? 'R' : 'Q';
    // print DNS information
    if(!args->verbose)
        printf("%s %s -> %s (%c %d/%d/%d/%d)\n",
               time_str,
               src_ip,
               dst_ip,
               qr,
               ntohs(question_count),
               ntohs(answer_count),
               ntohs(authority_count),
               ntohs(additional_count));
    else {
        printf("Timestamp: %s\n", time_str);
        printf("SrcIP: %s\n", src_ip);
        printf("DstIP: %s\n", dst_ip);
        printf("SrcPort: UDP/%d\n", ntohs(udp_hdr->uh_sport));
        printf("DstPort: UDP/%d\n", ntohs(udp_hdr->uh_dport));
        printf("Identifier: 0x%X\n", dns_id);

        // print flags
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
               (dns_flags & 0x8000) >> 15, (dns_flags & 0x7800) >> 11, (dns_flags & 0x0400) >> 10,
               (dns_flags & 0x0200) >> 9, (dns_flags & 0x0100) >> 8, (dns_flags & 0x0080) >> 7,
               (dns_flags & 0x0020) >> 5, (dns_flags & 0x0010) >> 4, dns_flags & 0x000F);

        printf("\n[Question Section]\n");
        const u_char *payload = process_question_section(dns_payload + 12, dns_payload, question_count);

        if (answer_count > 0) {
            payload = process_resource_record_section(payload, dns_payload, answer_count, "Answer");
        }
        if (authority_count > 0) {
            payload = process_resource_record_section(payload, dns_payload, authority_count, "Authority");
        }
        if (additional_count > 0) {
            process_resource_record_section(payload, dns_payload, additional_count, "Additional");
        }
        printf("====================\n");
    }
}

void dns_packet_handler(u_char *arguments, const struct pcap_pkthdr *header, const u_char *packet) {
    ProgramArguments *args = (ProgramArguments *) arguments;

    struct ip *ip_hdr = (struct ip *)(packet + 14);
    struct udphdr *udp_hdr = (struct udphdr *)(packet + 14 + ip_hdr->ip_hl * 4);

    // check that packet is udp and destination port is 53
    if(ntohs(udp_hdr->uh_dport) == 53 || ntohs(udp_hdr->uh_sport) == 53) {
        print_dns_information(header, ip_hdr, udp_hdr, packet + 14 + ip_hdr->ip_hl * 4 + 8, args);
    }
}

void capture_dns_packets(ProgramArguments args) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if(args.interface) {
        // opens interface for capturing
        handle = pcap_open_live(args.interface, 65536, 1, 1000, errbuf);
    } else {
        // opens pcap file for processing
        handle = pcap_open_offline(args.pcapfile, errbuf);
    }

    if (handle != NULL) {
        // starts packet capturing
        if (pcap_loop(handle, 0, dns_packet_handler, (u_char *) &args) == -1) {
            fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "Error: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
}