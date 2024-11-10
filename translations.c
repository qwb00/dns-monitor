//
// Created by Aleksander on 28.09.2024.
//

#include "translations.h"

void initialize_translation_set(TranslationSet *set) {
    set->count = 0;
    set->capacity = 100;
    set->entries = (TranslationEntry *) malloc(set->capacity * sizeof(TranslationEntry));
}

void free_translation_set(TranslationSet *set) {
    for (size_t i = 0; i < set->count; i++) {
        free(set->entries[i].domain);
        free(set->entries[i].ip);
    }
    free(set->entries);
}

int translation_exists(TranslationSet *set, const char *domain, const char *ip) {
    for (size_t i = 0; i < set->count; i++) {
        if (strcmp(set->entries[i].domain, domain) == 0 && strcmp(set->entries[i].ip, ip) == 0) {
            return 1;
        }
    }
    return 0;
}

int add_translation(TranslationSet *set, const char *domain, const char *ip, const char *filename) {
    if (translation_exists(set, domain, ip)) {
        return 0; // already exists
    }
    // Add to set
    if (set->count == set->capacity) {
        size_t new_capacity = set->capacity * 2;
        TranslationEntry *new_entries = (TranslationEntry *) realloc(set->entries, new_capacity * sizeof(TranslationEntry));
        if (!new_entries) {
            fprintf(stderr, "Error: Memory allocation failed while adding translation\n");
            return -1;
        }
        set->entries = new_entries;
        set->capacity = new_capacity;
    }
    set->entries[set->count].domain = strdup(domain);
    set->entries[set->count].ip = strdup(ip);
    set->count++;
    // Append to file if filename is provided
    if (filename != NULL) {
        FILE *file = fopen(filename, "a");
        if (file) {
            fprintf(file, "%s %s\n", domain, ip);
            fclose(file);
        } else {
            fprintf(stderr, "Error opening translation file %s for appending\n", filename);
        }
    }
    return 1; // added
}

void load_translations_from_file(TranslationSet *set, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        char line[1024];
        while (fgets(line, sizeof(line), file)) {
            // Remove newline
            line[strcspn(line, "\r\n")] = '\0';
            char *domain = strtok(line, " ");
            char *ip = strtok(NULL, " ");
            if (domain && ip) {
                add_translation(set, domain, ip, NULL); // NULL filename to avoid writing back to file
            }
        }
        fclose(file);
    } else {
        // File may not exist, that's fine
    }
}

