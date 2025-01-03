#include "file.h"


off_t get_file_size(const char *file_path) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Entering function to get the file size for file: %s", file_path);

    struct stat file_stat;
    int fd;

    // Try to open the file
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Attempting to open the file in read-only mode: %s", file_path);
    CHECK(fd = open(file_path, O_RDONLY), "Failed to open file", {return -1;}, ACCEPTABLE_ERROR, process);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "File opened successfully: %s", file_path);

    // Use fstat to get file metadata
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Attempting to get file statistics for file descriptor %d", fd);
    CHECK(fstat(fd, &file_stat), "fstat failed", {return -1;}, ACCEPTABLE_ERROR, process);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Successfully retrieved file statistics for file descriptor %d", fd);

    // Return the file size
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "File size for %s: %ld bytes", file_path, file_stat.st_size);

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Exiting function, returning file size for file: %s", file_path);

    return file_stat.st_size;
}



void split_path(const char *path, char **directory, char **filename) {
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Starting to split path: %s", path);

    char *last_sep;

    #ifdef _WIN32
        last_sep = strrchr(path, '\\');
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Detected Windows OS, using '\\' as separator");
    #else
        last_sep = strrchr(path, '/');
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Detected non-Windows OS, using '/' as separator");
    #endif

    if (last_sep != NULL) {
        // Found the last separator in the path
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Found last separator at position: %ld", last_sep - path);

        // Calculate directory length, including the separator
        size_t dir_length = last_sep - path + 1;

        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Calculated directory length: %zu", dir_length);

        // Allocate memory for directory and copy the directory part of the path
        *directory = (char *)malloc(dir_length + 1);
        if (*directory == NULL) {
            log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Memory allocation failed for directory", errno);
            return;
        }

        strncpy(*directory, path, dir_length);
        (*directory)[dir_length] = '\0'; // Null-terminate the directory string
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Directory extracted: %s", *directory);

        // Allocate memory for the filename and copy the filename part of the path
        *filename = strdup(last_sep + 1);
        if (*filename == NULL) {
            log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Memory allocation failed for filename", errno);
            free(*directory); // Free the previously allocated directory memory
            return;
        }

        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Filename extracted: %s", *filename);

    } else {
        // No separator found, the path is considered a filename only
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "No separator found, treating the entire path as filename");

        *directory = NULL;
        *filename = strdup(path);
        if (*filename == NULL) {
            log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Memory allocation failed for filename", errno);
            return;
        }

        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Filename is the entire path: %s", *filename);
    }

    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Exiting function after splitting path");
}




// Function to get the MTU for the network interface
size_t get_network_mtu(int sockfd) {
    int default_payload_size = atoi(GetConfigValue(config_file_path, "PAYLOAD"));

#ifdef __linux__
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    // Set the interface name (e.g., eth0)
    strcpy(ifr.ifr_name, "eth0"); // Change "eth0" to your network interface if needed

    // Fetch the MTU
    if (ioctl(sockfd, SIOCGIFMTU, &ifr) == -1) {
        perror("ioctl SIOCGIFMTU");
        return default_payload_size; // Fallback to default
    }

    printf("Detected MTU: %d bytes\n", ifr.ifr_mtu);
    return ifr.ifr_mtu;
#else
    // MTU detection is not available on macOS using ioctl in the same way.
    printf("MTU detection not supported on this platform. Using default payload size.\n");
    return default_payload_size;
#endif
}





// Function to adjust buffer size dynamically based on socket settings and MTU
size_t get_optimal_send_size(int sockfd) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Entering get_optimal_send_size function");

    size_t mtu_size = get_network_mtu(sockfd);
    int opt_size;
    socklen_t opt_len = sizeof(opt_size);

    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &opt_size, &opt_len) == -1) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "ERR_%d: Failed to get socket options (getsockopt): %s", errno, strerror(errno));
        opt_size = mtu_size; // Fallback to MTU
    } else {
        opt_size = opt_size < mtu_size ? opt_size : mtu_size;
    }
    log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Max send buffer size: %d bytes", opt_size);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "get_optimal_send_size function completed successfully");

    return opt_size;
}





int open_unique_file(const char *base_filename, char **newfile) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Entering open_unique_file function");
    char *filename = fstring("%s", base_filename);
    int fd, count = 0;

    while (1) {
        // Try to open the file
        fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (fd != -1) {
            // Successfully opened a unique file
            log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "File '%s' opened successfully for writing", filename);
            *newfile = filename;
            break;
        } else if (errno == EEXIST) {
            // File exists, generate a new filename
            count++;
            free(filename);
            filename = fstring("%s_%d", base_filename, count);
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "ERR_%d: File \"%s\" exists: %s. Trying to open a new file under the name", errno, filename, strerror(errno));
        } else {
            // Some other error occurred
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "ERR_%d: Error opening file \"%s\" for writing: %s", errno, filename, strerror(errno));
            fd = -1;
            *newfile = NULL;
            break;
        }
    }
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "open_unique_file function completed successfully");
    return fd;
}










size_t send_file(int sockfd, char * file_name_with_path){
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Entering send_file function");

    // Step-1: Open file and get file size
    int fd = 0;
    if ( (fd = open(file_name_with_path, O_RDONLY)) < 0) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "ERR_%d: Failed to open file \"%s\". %s", errno, file_name_with_path, strerror(errno));
        return 0;
    }
    struct stat file_stat;
    size_t file_size = 0;
    if ( fstat(fd, &file_stat) == -1 || !(file_size = file_stat.st_size)) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "ERR_%d: Failed to read \"%s\" file size. %s", errno, file_name_with_path, strerror(errno));
        return 0;
    }

    // Step-2: Separate filename and path from file_name_with_path
    char *path = NULL, *file_name = NULL;
    split_path(file_name_with_path, &path, &file_name);
    
    // Step-3: Send to recepient "FILE <name> <size>"
    char * command = fstring("FILE %s %zu", file_name, file_size);
    write_data(sockfd, (unsigned char *)command, strlen(command), server);

    // Step-4: Determine payload size (lesser of MTU and socket send buffer)
    size_t send_size = get_optimal_send_size(sockfd);

    // Step-5: Read payload size bytes from file and use write_data to transmit data
    size_t total_read = 0, bytes_read;
    unsigned char file_content[send_size];
    while(total_read < file_size) {
        bytes_read = (file_size - total_read) > send_size ? send_size : (file_size - total_read);
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "bytes_read-1: %zu, file_size: %zu", bytes_read, file_size);
        bytes_read = read(fd, file_content, bytes_read);
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "bytes_read-2: %zu", bytes_read);
        if (bytes_read <= 0){
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "ERR_%d: Read on \"%s\" failed. %s", errno, file_name_with_path, strerror(errno));
            return 0;
        }
        total_read += bytes_read;
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "total_read: %zu", total_read);
        write_data(sockfd, file_content, bytes_read, server);
    }

    // Step-6: Close file
    if (close(fd) == -1)
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "ERR_%d: Failed to close the file \"%s\": %s", errno, file_name_with_path, strerror(errno));
    
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "send_file function completed successfully");

    return total_read;
}
// FILE /opt/oracle/libnnz.dylib




size_t recv_file(int sockfd, char *file_name, size_t size){
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Entering recv_file function");

    // Open the file for writing in binary mode
    char *file_path = fstring("%s/%s", GetConfigValue(config_file_path, "TEMPDIR"), file_name);

    int save_flag = 0;
    char * save_filename = 0;
    int fd = open_unique_file(file_path, &save_filename);
    if(fd != -1) save_flag = 1;

    size_t bytes_recd = 0;
    while (bytes_recd < size){
        size_t bytes = 0;
        unsigned char *file_content = NULL;
        read_data(sockfd, &file_content, &bytes, server);
        bytes_recd += bytes;
        if(save_flag) {
            if(write(fd, file_content, bytes) == -1) {
                log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "ERR_%d: Writing to file \"%s\" failed: %s", errno, file_path, strerror(errno));
            } else {
                log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "... wrote %zu bytes", bytes_recd);
            }
        }
        if(file_content) free(file_content);
    }
    close(fd);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "recv_file function completed successfully. Wrote %zu bytes", bytes_recd);
    return bytes_recd;
}