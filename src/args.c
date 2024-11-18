// Aleksander Postelga xposte00

#include "args.h"

// prints help message
void print_usage(char *prog_name) {
    printf("Usage: %s (-i <interface> | -p <pcap file>) [-v] [-d <domains file>] [-t <translations file>]\n", prog_name);
    printf("  -i <interface>           Interface to listen on\n");
    printf("  -p <pcap file>           PCAP file to process\n");
    printf("  -v                       Verbose mode (detailed DNS messages)\n");
    printf("  -d <domains file>        File with domain names\n");
    printf("  -t <translations file>   File with domain-to-IP translations\n");
    printf("  -h                       Display this help message\n");
}

// parses command line arguments
ProgramArguments parse_args(int argc, char **argv) {
    int opt;
    ProgramArguments options;

    options.verbose = 0;
    options.interface = NULL;
    options.pcap_file = NULL;
    options.domains_file = NULL;
    options.translations_file = NULL;

    while((opt = getopt(argc, argv, "i:p:vd:t:h")) != -1) {
        switch(opt) {
            case 'i':
                options.interface = optarg;
                break;
            case 'p':
                options.pcap_file = optarg;
                break;
            case 'v':
                options.verbose = 1;
                break;
            case 'd':
                options.domains_file = optarg;
                break;
            case 't':
                options.translations_file = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_usage(argv[0]);
                exit(BAD_ARGUMENTS);
        }
    }

    if(!options.interface && !options.pcap_file) {
        fprintf(stderr, "Error: You must specify either -i <interface> or -p <pcapfile>.\n");
        print_usage(argv[0]);
        exit(BAD_ARGUMENTS);
    }

    if (options.interface && options.pcap_file) {
        fprintf(stderr, "Error: You cannot specify both -i <interface> and -p <pcapfile>.\n");
        print_usage(argv[0]);
        exit(BAD_ARGUMENTS);
    }
    return options;
}