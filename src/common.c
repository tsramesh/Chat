#include "common.h"

// Log level definitions
char *log_levels[] = {
    "LOG_NONE: No logging enabled",
    "LOG_FATAL: Fatal errors only",
    "LOG_CRITICAL: Critical & Fatal errors reported", "",
    "LOG_WARN: All warnings in addition to critical & fatal errors reported", "", "", "",
    "LOG_ERROR: General errors, including warning, critical & fatal errors reported", "", "", "", "", "", "", "",
    "LOG_INFO: General errors with first level of granularity reported", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
    "LOG_DEBUG: Most granular logging - please exercise restraint"
};

char * fstring(const char* format, ...) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting fstring() computation");

    va_list args;
    va_start(args, format);

    // Calculate the size of the formatted string
    int size = vsnprintf(NULL, 0, format, args) + 1; // +1 for null terminator
    va_end(args);

    if (size <= 0) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Unable to determine the required buffer size: %s", errno, strerror(errno));
        return NULL; // Handle formatting errors
    }

    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Determined %d bytes are required to create the fstring", size);

    // Allocate memory for the formatted string
    char* result = (char*)malloc(size);
    if (!result) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Memory allocation (required buffer size %d bytes) failed: %s", errno, size, strerror(errno));
        return NULL; // Handle memory allocation failure
    }

    // Write the formatted string into the allocated memory
    va_start(args, format);
    vsnprintf(result, size, format, args);
    va_end(args);

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed fstring() successfully");
    return result; // Caller is responsible for freeing the memory
}

char* GetConfigValue(const char *filename, const char *key) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting GetConfigValue() with filename: %s and key: %s", filename, key);

    FILE *file = fopen(filename, "r");
    if (!file) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Unable to open file %s: %s", errno, filename, strerror(errno));
        return NULL;
    }

    size_t key_len = strlen(key);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Key length calculated: %zu", key_len);

    char *line = NULL;
    size_t len = 0;
    char *value = NULL;

    while (getline(&line, &len, file) != -1) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Processing line: %s", line);

        char *ptr = line;

        while (isspace(*ptr)) ptr++;

        if (strncmp(ptr, key, key_len) == 0) {
            ptr += key_len;

            while (isspace(*ptr)) ptr++;

            if (*ptr == '=') {
                ptr++;

                while (isspace(*ptr)) ptr++;

                char *val_start = ptr;

                while (*ptr && *ptr != '\n') ptr++;

                while (ptr > val_start && isspace(*(ptr - 1))) ptr--;

                size_t length = ptr - val_start;

                log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Extracted value length: %zu", length);

                value = realloc(value, length + 1);
                if (!value) {
                    log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Memory allocation for value string failed: %s", errno, strerror(errno));
                    free(line);
                    fclose(file);
                    return NULL;
                }

                strncpy(value, val_start, length);
                value[length] = '\0';

                log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Extracted value: %s", value);
                break;
            }
        }
    }

    free(line);
    fclose(file);

    if (!value) {
        log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "Key %s not found in file %s", key, filename);
    }

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed GetConfigValue() successfully");
    return value;
}

char **parse_bind_variables(const char *input, int *count, char id) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting parse_bind_variables() with input: %s", input);

    if (!input || !count) {
        log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "Invalid arguments passed to parse_bind_variables");
        return NULL;
    }

    *count = 0;

    char *input_copy = strdup(input);
    if (!input_copy) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Memory allocation for input copy failed: %s", errno, strerror(errno));
        return NULL;
    }

    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Copied input string: %s", input_copy);

    char *token = strtok(input_copy, " \t\n\r");
    char **result = NULL;

    while (token) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Processing token: %s", token);

        if (token[0] == id) {
            (*count)++;

            char **new_result = realloc(result, (*count) * sizeof(char*));
            if (!new_result) {
                log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Memory reallocation failed for token array: %s", errno, strerror(errno));
                for (int i = 0; i < *count - 1; i++) free(result[i]);
                free(result);
                free(input_copy);
                return NULL;
            }

            result = new_result;

            result[*count - 1] = strdup(token);
            if (!result[*count - 1]) {
                log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Memory allocation failed for token: %s", errno, strerror(errno));
                for (int i = 0; i < *count - 1; i++) free(result[i]);
                free(result);
                free(input_copy);
                return NULL;
            }
        }

        token = strtok(NULL, " \t\n\r");
    }

    free(input_copy);

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed parse_bind_variables() successfully with %d tokens", *count);
    return result;
}


void log_message(int log_level, const char *pid, const char *func, const char *file, int line, const char *fmt, ...) {
    char timestamp[26];
    char *env = NULL;
    struct timeval timeOfDay;
    struct tm time;
    int env_log_level = (env = getenv("MSG_DEBUG_LEVEL")) ? atoi(env) : 0;

    if (log_level <= env_log_level) {
        // Get the current time and format the timestamp
        gettimeofday(&timeOfDay, NULL);
        localtime_r(&timeOfDay.tv_sec, &time);

        snprintf(timestamp, sizeof(timestamp), "%.4d-%.2d-%.2d %.2d:%.2d:%.2d.%.3d", 
                 time.tm_year + 1900, time.tm_mon + 1, time.tm_mday,
                 time.tm_hour, time.tm_min, time.tm_sec, (int)(timeOfDay.tv_usec / 1000));

        // Start variable argument list
        va_list args;
        va_start(args, fmt);

        // Print the log message with timestamp and other details
        printf(COLOR_WHITE "%s %s | %s, %s Line %d | " COLOR_MAGENTA, 
               pid, timestamp, file, func, line);

        // Print the formatted message using the variable argument list
        vprintf(fmt, args);

        // Reset color and end the line
        printf(COLOR_WHITE "\n");

        // End variable argument list
        va_end(args);
    }
}