// Aleksander Postelga xposte00

#include "domains.h"

void initialize_domain_set(DomainSet *set) {
    set->count = 0;
    set->capacity = 100;
    set->domains = (char **) malloc(set->capacity * sizeof(char *));
}

void free_domain_set(DomainSet *set) {
    for (size_t i = 0; i < set->count; i++) {
        free(set->domains[i]);
    }
    free(set->domains);
}

int domain_exists(DomainSet *set, const char *domain) {
    for (size_t i = 0; i < set->count; i++) {
        if (strcmp(set->domains[i], domain) == 0) {
            return 1;
        }
    }
    return 0;
}

int add_domain(DomainSet *set, const char *domain, const char *filename) {
    if (domain == NULL || strlen(domain) == 0) {
        return 0; // Invalid domain, do not add
    }

    if (domain_exists(set, domain)) {
        return 0; // already exists
    }

    // Add to set
    if (set->count == set->capacity) {
        size_t new_capacity = set->capacity * 2;
        char **new_domains = realloc(set->domains, new_capacity * sizeof(char *));
        if (!new_domains) {
            fprintf(stderr, "Error reallocating memory for domain set\n");
            return -1; // Allocation failed
        }
        set->domains = new_domains;
        set->capacity = new_capacity;
    }
    set->domains[set->count++] = strdup(domain);

    // Append to file if filename is provided
    if (filename != NULL) {
        FILE *file = fopen(filename, "a+");
        if (file) {
            fprintf(file, "%s\n", domain);
            fclose(file);
        } else {
            fprintf(stderr, "Error: opening domain file %s for appending\n", filename);
        }
    }
    return 1; // added
}

void load_domains_from_file(DomainSet *set, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        char line[1024];
        while (fgets(line, sizeof(line), file)) {
            // Remove newline
            line[strcspn(line, "\r\n")] = '\0';
            add_domain(set, line, NULL); // NULL needed to avoid appending to file
        }
        fclose(file);
    } else {
        // file may not exist, that's fine :)
    }
}
