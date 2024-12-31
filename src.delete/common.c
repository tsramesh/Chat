#include "common.h"

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