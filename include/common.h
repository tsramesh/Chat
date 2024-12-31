/**
 * @file common.h
 * @brief Common header file providing shared macros, includes, and external declarations.
 *
 * This file contains commonly used macros, includes, and external variable declarations 
 * that are shared across multiple source files in the project. It simplifies the inclusion of standard 
 * libraries and defines several utility macros for error handling, logging, and system operations.
 */

#ifndef COMMON_H
#define COMMON_H

// Standard and platform-specific libraries
#include <stdio.h>         // Standard I/O functions (printf, fprintf, etc.)
#include <errno.h>         // Error codes
#include <fcntl.h>         // File control options (e.g., O_NONBLOCK)
#include <pthread.h>       // Thread management
#include <stddef.h>        // For size_t type
#include <unistd.h>        // System calls (read, write, etc.)
#include <stdlib.h>        // Memory allocation and process control (malloc, free, exit)
#include <string.h>        // String manipulation (memcpy, etc.)
#include <stdint.h>        // Fixed-width integer types (uint8_t, uint32_t, etc.)
#include <stdbool.h>       // Boolean type support
#include <zlib.h>          // Compression library (zlib)
#include <stdarg.h>
#include <sys/types.h>     // Definition of system types
#include <sys/socket.h>    // Socket functions
#include <sys/ioctl.h>     // Input/output control (e.g., FIONREAD)
#include <sys/stat.h>
#include <netinet/in.h>    // Internet address family (struct sockaddr_in)
#include <arpa/inet.h>     // Internet address manipulation (inet_ntoa, inet_pton)
#include <ifaddrs.h>
#include <net/if.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/aes.h>   // AES encryption/decryption functions
#include <openssl/sha.h>   // SHA256 function and constants
#include <openssl/evp.h>   // OpenSSL EVP API for cryptography (encryption, hashing, etc.)
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "ocilib.h"
#include "dpi.h"

#define COLOR_RESET         "\033[0m"
#define COLOR_BLACK         "\033[0;30m"
#define COLOR_RED           "\033[0;31m"
#define COLOR_GREEN         "\033[0;32m"
#define COLOR_YELLOW        "\033[0;33m"
#define COLOR_BLUE          "\033[0;34m"
#define COLOR_MAGENTA       "\033[0;35m"
#define COLOR_CYAN          "\033[0;36m"
#define COLOR_LIGHT_GRAY    "\033[0;37m"
#define COLOR_DARK_GRAY     "\033[1;30m"
#define COLOR_LIGHT_RED     "\033[1;31m"
#define COLOR_LIGHT_GREEN   "\033[1;32m"
#define COLOR_LIGHT_YELLOW  "\033[1;33m"
#define COLOR_LIGHT_BLUE    "\033[1;34m"
#define COLOR_LIGHT_MAGENTA "\033[1;35m"
#define COLOR_LIGHT_CYAN    "\033[1;36m"
#define COLOR_WHITE         "\033[1;37m"

// Port and backlog definition for socket connections
#define PORT 6000          /**< Default server port number. */
#define BACKLOG 100        /**< Maximum number of pending connections for server socket. */

// Error codes
#define CRITICAL_ERROR 1   /**< Error level indicating a critical failure that requires immediate termination. */
#define ACCEPTABLE_ERROR 0 /**< Error level indicating a non-critical failure. */

#define LOG_FATAL       0x0001 //  1: Log fatal errors only
#define LOG_CRITICAL    0x0002 //  2: Log critical errors omly
#define LOG_WARN        0x0004 //  4: Log warnings only
#define LOG_ERROR       0x0008 //  8: Log all types of errors
#define LOG_INFO        0x0010 // 16: Log traversing of functions
#define LOG_DEBUG       0x0020 // 32: Log every line - most granular logging

// Declaration of the `Alive` variable to control the server loop
extern volatile int Alive; /**< A flag indicating if the server should continue running. */

// Flag to indicate whether the current process is a server or client
extern int server; /**< A flag that identifies whether the function is being invoked by the server or client. */
extern int server_fd;
extern char * server_ip;
extern int server_port;
extern char * process;
extern char * config_file_path;

// Process ID markers
extern int cpid; // Stores child process ID
extern int ppid; // Stores parent process ID 

// Macro for logging messages with timestamps, file, function, and line number
#define LOG(stream, fmt, ...) do { \
    time_t t = time(NULL); \
    struct tm *tm_info = localtime(&t); \
    char buffer[26]; \
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info); \
    fprintf(stream, COLOR_WHITE "[%s] " COLOR_MAGENTA fmt COLOR_WHITE " | Function: %s, File: %s, Line: %d\n", \
        buffer, __VA_ARGS__, __func__, __FILE__, __LINE__); \
} while (0)

/**
 * @brief Macro to log error location with function, file, and line details.
 * 
 * This macro logs the current time, function name, file name, and line number 
 * when an error occurs, providing context to the point where the error is encountered.
 */
#define ERROR_AT(process) do { \
    time_t t = time(NULL); \
    struct tm *tm_info = localtime(&t); \
    char buffer[26]; \
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info); \
    fprintf(stderr, "[%s", buffer); \
    fprintf(stderr, " | %s: Function: %s, File: %s, Line: %d] ", process, __func__, __FILE__, __LINE__); \
} while (0)

/**
 * @brief Macro to check the result of a function and handle errors.
 * 
 * This macro is used to check the return value of a function. If the function fails (i.e., returns a negative value),
 * it logs the error, performs cleanup (if provided), and optionally exits the program based on the `exit_on_fail` flag.
 *
 * @param func The function to check (its return value will be evaluated).
 * @param msg Error message to display if the function fails.
 * @param cleanup Code to execute if the function fails (e.g., freeing memory, closing resources).
 * @param exit_on_fail Flag to indicate if the program should exit after failure (1 = exit, 0 = continue).
 */
#define CHECK(func, msg, cleanup, exit_on_fail, process) \
    do { \
        if ((func) < 0) {             \
            ERROR_AT(process);               \
            perror(msg);              \
            cleanup;                  \
            if (exit_on_fail) exit(EXIT_FAILURE); \
        } \
    } while (0)

char * fstring(const char* format, ...);
char * GetConfigValue(const char *filename, const char *key);
char ** parse_bind_variables(const char *input, int *count, char id);
void log_message(int log_level, const char *pid, const char *func, const char *file, int line, const char *fmt, ...);

#endif // COMMON_H

