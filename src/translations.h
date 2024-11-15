// Aleksander Postelga xposte00

#ifndef TRANSLATIONS_H
#define TRANSLATIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *domain;
    char *ip;
} TranslationEntry;

typedef struct {
    size_t count;
    size_t capacity;
    TranslationEntry *entries;
} TranslationSet;

void initialize_translation_set(TranslationSet *set);
void load_translations_from_file(TranslationSet *set, const char *filename);
int add_translation(TranslationSet *set, const char *domain, const char *ip, const char *filename);
void free_translation_set(TranslationSet *set);
int translation_exists(TranslationSet *set, const char *domain, const char *ip);

#endif // TRANSLATIONS_H

