#include "dns_capture.h"

volatile sig_atomic_t stop_capture = 0;
// Signal handler function
void handle_signal(int signal) {
    stop_capture = 1;
}

void free_all_resources(DnsMonitorContext *context) {
    free_domain_set(&context->domain_set);
    free_translation_set(&context->translation_set);
}

// Function to process IPv4 packets
void process_ipv4_packet(const u_char *packet, const struct pcap_pkthdr *header, DnsMonitorContext *context) {
    // Skip Ethernet header
    const struct ip *ip_hdr = (struct ip *) (packet + sizeof(struct ether_header));

    // Getting UDP header pointer
    // calculating the length of ip header (ip_hl is in 32-bit words, so multiply by 4)
    int ip_header_length = ip_hdr->ip_hl * 4;
    const struct udphdr *udp_hdr = (struct udphdr *) ((u_char *) ip_hdr + ip_header_length);

    // Get DNS payload
    const u_char *dns_payload = (const u_char *) udp_hdr + sizeof(struct udphdr);

    // Process DNS packet
    print_dns_information(header, ip_hdr, udp_hdr, dns_payload, context);
}

const u_char *skip_ipv6_extension_headers(const u_char *payload, uint8_t *next_header, const u_char *end_of_packet) {
    while (*next_header != IPPROTO_UDP) {
        switch (*next_header) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS:
                if (payload + 2 > end_of_packet) return NULL;
                uint8_t ext_hdr_len = payload[1]; // get hdr ext len
                *next_header = payload[0]; // next header
                payload += (ext_hdr_len + 1) * 8; // move to next header
                break;
            case IPPROTO_FRAGMENT:
                if (payload + 8 > end_of_packet) return NULL;
                *next_header = payload[0]; // next header
                payload += 8; // next header + reserved + fragment offset + res + m flag + identification = 8 bytes
                break;
            case IPPROTO_AH:
                if (payload + 2 > end_of_packet) return NULL;
                uint8_t ext_hdr_len_ah = payload[1]; // ext hdr len
                *next_header = payload[0]; // next header
                // ext_hdr_len_ah is in 32-bit words,
                // excluding the first 2 words, so add 2 and multiply by 4
                payload += (ext_hdr_len_ah + 2) * 4;
                break;
            default: //other headers are not supported
                return NULL;
        }

        if (payload >= end_of_packet) return NULL;
    }
    return payload;
}

// Function to process IPv6 packets
void process_ipv6_packet(const u_char *packet, const struct pcap_pkthdr *header, DnsMonitorContext *context) {
    // Skip Ethernet header
    const struct ip6_hdr *ip6_hdr = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

    uint8_t next_header = ip6_hdr->ip6_nxt;
    const u_char *payload = (const u_char *) (ip6_hdr + 1);
    const u_char *end_of_packet = packet + header->caplen;

    payload = skip_ipv6_extension_headers(payload, &next_header, end_of_packet);
    if (!payload) return;

    const struct udphdr *udp_hdr = (const struct udphdr *) payload;

    // Get DNS payload
    const u_char *dns_payload = (const u_char *) udp_hdr + sizeof(struct udphdr);

    // Process DNS packet
    print_dns_information_ipv6(header, ip6_hdr, udp_hdr, dns_payload, context);
}

// Modify the dns_packet_handler function to handle both IPv4 and IPv6
void dns_packet_handler(u_char *context_ptr, const struct pcap_pkthdr *header, const u_char *packet) {
    if (stop_capture) {
        pcap_breakloop(((DnsMonitorContext *) context_ptr)->pcap_handle);
        return;
    }

    DnsMonitorContext *context = (DnsMonitorContext *) context_ptr;

    int link_type = pcap_datalink(context->pcap_handle);

    if (link_type == DLT_EN10MB) {
        // Ethernet
        const struct ether_header *eth_header = (const struct ether_header *) packet;

        // Check the EtherType to determine whether it's IPv4 or IPv6
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            // IPv4
            process_ipv4_packet(packet, header, context);
        } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
            // IPv6
            process_ipv6_packet(packet, header, context);
        }
    } else {
        fprintf(stderr, "Unsupported link type: %d\n", link_type);
        return;
    }
}

void capture_dns_packets(DnsMonitorContext *context) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if(context->args->interface) {
        handle = pcap_open_live(context->args->interface, 65536, 1, 1000, errbuf);
    } else {
        handle = pcap_open_offline(context->args->pcap_file, errbuf);
    }

    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        free_all_resources(context);
        exit(EXIT_FAILURE);
    }

    // saves the pcap handle in the context
    context->pcap_handle = handle;

    // setting filter for DNS packets over UDP
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        free_all_resources(context);
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        free_all_resources(context);
        exit(EXIT_FAILURE);
    }

    // Starts packet capturing
    if (pcap_loop(handle, -1, dns_packet_handler, (u_char *) context) == -1) {
        fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
        free_all_resources(context);
        exit(EXIT_FAILURE);
    }

    pcap_close(handle);
}