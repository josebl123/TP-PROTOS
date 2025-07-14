// user_metrics_table.c
#include "user_metrics_table.h"
#include <stdlib.h>
#include <string.h>
#include "utils/logger.h"

typedef struct user_metrics_entry {
    char *username;
    user_metrics metrics;
    struct user_metrics_entry *next;
} user_metrics_entry;

static user_metrics_entry *table[METRICS_TABLE_SIZE];

static unsigned long hash_username(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % METRICS_TABLE_SIZE;
}

void init_user_metrics_table(void) {
    for (int i = 0; i < METRICS_TABLE_SIZE; i++) {
        table[i] = NULL;
    }
}

user_metrics *get_or_create_user_metrics(const char *username) {
    if (!username) return NULL;
    unsigned long index = hash_username(username);
    user_metrics_entry *entry = table[index];
    while (entry) {
        if (strcmp(entry->username, username) == 0) {
            return &entry->metrics;
        }
        entry = entry->next;
    }
    // Not found, create new
    entry = malloc(sizeof(user_metrics_entry));
    if (!entry) return NULL;
    entry->username = strdup(username);
    if (!entry->username) {
        free(entry);
        return NULL;
    }
    user_metrics_init(&entry->metrics);
    entry->next = table[index];
    table[index] = entry;
    return &entry->metrics;
}

user_metrics *find_user_metrics(const char *username) {
    if (!username) return NULL;
    unsigned long index = hash_username(username);
    user_metrics_entry *entry = table[index];
    while (entry) {
        if (strcmp(entry->username, username) == 0) {
            return &entry->metrics;
        }
        entry = entry->next;
    }
    return NULL;
}

void print_all_user_metrics(FILE *out) {
    for (int i = 0; i < METRICS_TABLE_SIZE; ++i) {
        user_metrics_entry *entry = table[i];
        while (entry) {
            print_user_metrics_tabbed(&entry->metrics, entry->username, out);
            entry = entry->next;
        }
    }
}

void free_user_metrics_table(void) {
    for (int i = 0; i < METRICS_TABLE_SIZE; ++i) {
        user_metrics_entry *entry = table[i];
        while (entry) {
            user_metrics_entry *next = entry->next;
            free(entry->username);
            user_metrics_free(&entry->metrics);
            free(entry);
            entry = next;
        }
        table[i] = NULL;
    }
}
void remove_user_metrics(const char *username) {
    if (!username) return;
    unsigned long index = hash_username(username);
    user_metrics_entry *entry = table[index];
    user_metrics_entry *prev = NULL;
    while (entry) {
        if (strcmp(entry->username, username) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                table[index] = entry->next;
            }
            log(INFO, "REMOVED USER METRICS FOR %s\n", username);
            free(entry->username);
            user_metrics_free(&entry->metrics);
            free(entry);
            return;
        }
        log(INFO, "did not find it ups");
        prev = entry;
        entry = entry->next;
    }
}
