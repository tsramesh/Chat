#include "common.h"

typedef struct {
    char *key;
    char *value;
} ConfigEntry;

typedef struct {
    ConfigEntry *entries;
    size_t size;
} Config;

void read_config_file(const char *filename, Config *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char line[256];
    size_t count = 0;

    while (fgets(line, sizeof(line), file)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");
        if (key && value) {
            config->entries = realloc(config->entries, (count + 1) * sizeof(ConfigEntry));
            config->entries[count].key = strdup(key);
            config->entries[count].value = strdup(value);
            count++;
        }
    }

    config->size = count;
    fclose(file);
}

void free_config(Config *config) {
    for (size_t i = 0; i < config->size; i++) {
        free(config->entries[i].key);
        free(config->entries[i].value);
    }
    free(config->entries);
}
