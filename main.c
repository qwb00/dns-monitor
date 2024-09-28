//
// Created by Aleksander on 26.09.2024.
//

#import "args.h"
#include <stdio.h>
#include <pcap/pcap.h>

int main(int argc, char **argv) {
    ProgramArguments args = parse_args(argc, argv);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if(args.interface) {
        handle = pcap_open_live(args.interface, 65536, 1, 1000, errbuf);
    } else if(args.pcapfile) {
        handle = pcap_open_offline(args.pcapfile, errbuf);
    } else {
        fprintf(stderr, "Error: You must specify either -i <interface> or -p <pcapfile>.\n");
        print_usage(argv[0]);
        return BAD_ARGUMENTS;
    }

    if (!handle) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if(pcap_loop(handle, 0, packet_handler, (u_char *)&args) == -1) {
        fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    return 0;
}
