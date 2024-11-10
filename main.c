//
// Created by Aleksander on 26.09.2024.
//
#include "args.h"
#include "dns_capture.h"
#include "domains.h"
#include "translations.h"

int main(int argc, char **argv) {
    ProgramArguments args = parse_args(argc, argv);

    // Initialize context
    DnsMonitorContext context;
    context.args = &args;
    initialize_domain_set(&context.domain_set);
    initialize_translation_set(&context.translation_set);

    // Initialize domain set
    if (args.domains_file) {
        load_domains_from_file(&context.domain_set, args.domains_file);
    }

    // Initialize translation set
    if (args.translations_file) {
        load_translations_from_file(&context.translation_set, args.translations_file);
    }

    // Set up signal handling to clean up on interruption
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1 ||
        sigaction(SIGQUIT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    capture_dns_packets(&context);

    // Free memory
    free_all_resources(&context);

    return 0;
}

