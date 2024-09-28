//
// Created by Aleksander on 26.09.2024.
//

#include "args.h"

// prints help message
void print_usage(char *prog_name) {
    printf("Usage: %s (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]\n", prog_name);
    printf("  -i <interface>        Interface to listen on\n");
    printf("  -p <pcapfile>         PCAP file to process\n");
    printf("  -v                    Verbose mode (detailed DNS messages)\n");
    printf("  -d <domainsfile>      File with domain names\n");
    printf("  -t <translationsfile> File with domain-to-IP translations\n");
}

// parses command line arguments
ProgramArguments parse_args(int argc, char **argv) {
    int opt;
    ProgramArguments options;

    options.verbose = 0;
    options.interface = NULL;
    options.pcapfile = NULL;
    options.domainsfile = NULL;
    options.translationsfile = NULL;

    while((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch(opt) {
            case 'i':
                options.interface = optarg;
                break;
            case 'p':
                options.pcapfile = optarg;
                break;
            case 'v':
                options.verbose = 1;
                break;
            case 'd':
                options.domainsfile = optarg;
                break;
            case 't':
                options.translationsfile = optarg;
                break;
            default:
                printf("Error: Unknown option -%c\n", optopt);
                print_usage(argv[0]);
                exit(BAD_ARGUMENTS);
        }
    }

    if(!options.interface && !options.pcapfile) {
        fprintf(stderr, "Error: You must specify either -i <interface> or -p <pcapfile>.\n");
        print_usage(argv[0]);
        exit(BAD_ARGUMENTS);
    }

    if (options.interface && options.pcapfile) {
        fprintf(stderr, "Error: You cannot specify both -i <interface> and -p <pcapfile>.\n");
        print_usage(argv[0]);
        exit(BAD_ARGUMENTS);
    }
    return options;
}