//
// Created by Aleksander on 26.09.2024.
//

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
    char *pcapfile;
    char *domainsfile;
    char *translationsfile;
} ProgramArguments;

ProgramArguments parse_args(int argc, char **argv);
void print_usage(char *prog_name);

#endif //DNS_MONITOR_ARGS_H
