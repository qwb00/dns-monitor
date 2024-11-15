// Aleksander Postelga xposte00

#ifndef DOMAINS_H
#define DOMAINS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t count;
    size_t capacity;
    char **domains;
} DomainSet;

void initialize_domain_set(DomainSet *set);
void load_domains_from_file(DomainSet *set, const char *filename);
int add_domain(DomainSet *set, const char *domain, const char *filename);
void free_domain_set(DomainSet *set);
int domain_exists(DomainSet *set, const char *domain);

#endif // DOMAINS_H

