// Aleksander Postelga xposte00

#ifndef DNS_MONITOR_ARGS_H
#define DNS_MONITOR_ARGS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define EXIT_FAILURE 1
#define BAD_ARGUMENTS 2

typedef struct {
    int verbose;
    char *interface;
    char *pcap_file;
    char *domains_file;
    char *translations_file;
} ProgramArguments;

ProgramArguments parse_args(int argc, char **argv);
void print_usage(char *prog_name);

#endif //DNS_MONITOR_ARGS_H

