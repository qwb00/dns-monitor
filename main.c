//
// Created by Aleksander on 26.09.2024.
//

#import "args.h"
#import "dns_capture.h"
#include <stdio.h>

int main(int argc, char **argv) {
    ProgramArguments args = parse_args(argc, argv);

    capture_dns_packets(args);

    return 0;
}
