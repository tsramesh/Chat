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
    va_list args;
    va_start(args, format);

    // Calculate the size of the formatted string
    int size = vsnprintf(NULL, 0, format, args) + 1; // +1 for null terminator
    va_end(args);

    if (size <= 0) {
        return NULL; // Handle formatting errors
    }

    // Allocate memory for the formatted string
    char* result = (char*)malloc(size);
    if (!result) {
        return NULL; // Handle memory allocation failure
    }

    // Write the formatted string into the allocated memory
    va_start(args, format);
    vsnprintf(result, size, format, args);
    va_end(args);

    return result; // Caller is responsible for freeing the memory
}



/**
 * GetConfigValue
 *
 * Reads a key-value pair from a configuration file in the format "KEY = VALUE".
 *
 * @param filename The path to the configuration file.
 * @param key The key whose corresponding value needs to be retrieved.
 * @return A dynamically allocated string containing the value associated with the key,
 *         or NULL if the key is not found or an error occurs. The caller must free the returned memory.
 */
char* GetConfigValue(const char *filename, const char *key) {
    // Open the file in read mode
    FILE *file = fopen(filename, "r");
    if (!file) return NULL; // Return NULL if the file cannot be opened

    size_t key_len = strlen(key); // Length of the key for comparison
    char *line = NULL;           // Pointer to hold each line read from the file
    size_t len = 0;              // Initial buffer size for getline to allocate memory dynamically
    char *value = NULL;          // Pointer to hold the extracted value (to be returned)

    // Read the file line by line using getline
    while (getline(&line, &len, file) != -1) {
        char *ptr = line; // Pointer to traverse the line

        // Skip leading whitespace in the line
        while (isspace(*ptr)) ptr++;

        // Check if the current line starts with the key
        if (strncmp(ptr, key, key_len) == 0) {
            ptr += key_len; // Move the pointer past the key

            // Skip any whitespace before the '=' character
            while (isspace(*ptr)) ptr++;
            if (*ptr == '=') { // Ensure '=' is present
                ptr++; // Move past '='

                // Skip any whitespace after the '=' character
                while (isspace(*ptr)) ptr++;

                char *val_start = ptr; // Mark the beginning of the value

                // Move the pointer to the end of the value or the newline character
                while (*ptr && *ptr != '\n') ptr++;

                // Trim trailing whitespace from the end of the value
                while (ptr > val_start && isspace(*(ptr - 1))) ptr--;

                size_t length = ptr - val_start; // Calculate the length of the value

                // Dynamically allocate memory for the value string
                value = malloc(length + 1); // +1 for null terminator
                if (!value) { // Handle memory allocation failure
                    free(line); // Free dynamically allocated line buffer
                    fclose(file); // Close the file
                    return NULL; // Return NULL on memory allocation failure
                }

                // Copy the value into the allocated memory
                strncpy(value, val_start, length);
                value[length] = '\0'; // Null-terminate the string

                break; // Exit the loop after finding the key
            }
        }
    }

    // Free the dynamically allocated memory for the line buffer
    free(line);

    // Close the file
    fclose(file);

    // Return the extracted value (or NULL if the key was not found)
    return value;
}

/**
 * ParseTokens
 *
 * Parses the input string and extracts all tokens starting with `:`.
 *
 * @param input The input string to parse.
 * @param count A pointer to an integer where the number of tokens will be stored.
 * @param id A character to be used to identify the delimiter.
 * @return A dynamically allocated array of strings containing tokens starting with `:`.
 *         The caller is responsible for freeing each token and the array itself.
 */
char ** parse_bind_variables(const char *input, int *count, char id) {
    if (!input || !count) return NULL;

    // Initialize token count to 0
    *count = 0;

    // Copy the input string since strtok modifies the string
    char *input_copy = strdup(input);
    if (!input_copy) return NULL;

    // Tokenize the string using space and newline as delimiters
    char *token = strtok(input_copy, " \t\n\r");
    char **result = NULL;

    while (token) {
        // Check if the token starts with `:`
        if (token[0] == id) {
            // Increase the count
            (*count)++;

            // Reallocate memory for the result array
            char **new_result = realloc(result, (*count) * sizeof(char*));
            if (!new_result) {
                // Free previously allocated memory on failure
                for (int i = 0; i < *count - 1; i++) free(result[i]);
                free(result);
                free(input_copy);
                return NULL;
            }

            result = new_result;

            // Allocate memory for the token and store it
            result[*count - 1] = strdup(token);
            if (!result[*count - 1]) {
                // Free previously allocated memory on failure
                for (int i = 0; i < *count - 1; i++) free(result[i]);
                free(result);
                free(input_copy);
                return NULL;
            }
        }

        // Get the next token
        token = strtok(NULL, " \t\n\r");
    }

    // Free the copied input string
    free(input_copy);

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