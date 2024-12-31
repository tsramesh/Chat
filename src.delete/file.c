#include "file.h"

void split_path(const char *path, char **directory, char **filename) {
    char *last_sep;

    #ifdef _WIN32
        last_sep = strrchr(path, '\\');
    #else
        last_sep = strrchr(path, '/');
    #endif

    if (last_sep != NULL) {
        // Separate directory and filename
        size_t dir_length = last_sep - path + 1; // Include the separator in the directory

        *directory = (char *)malloc(dir_length + 1);
        strncpy(*directory, path, dir_length);
        (*directory)[dir_length] = '\0';

        *filename = strdup(last_sep + 1);
    } else {
        // No separator found, the path is just a filename
        *directory = NULL;
        *filename = strdup(path);
    }
}

off_t get_file_size(const char *file_path) {
    struct stat file_stat;
    int fd;
    CHECK(fd = open(file_name, O_RDONLY), "Failed to open file", {return -1;}, ACCEPTABLE_ERROR, process);
    // Use fstat to get file metadata
    CHECK(fstat(file_descriptor, &file_stat), "fstat failed", {return -1;}, ACCEPTABLE_ERROR, process);
    // Return the file size
    return file_stat.st_size;
}

size_t send_file(int sockfd, const char *file_path, unsigned char **filecontent) {
    FILE *file = fopen(file_path, "rb");
    CHECK((file != NULL ? 0 : -1), "Error opening file", /* cleanup */ , 1, process);
    fseek(file, 0, SEEK_END);
    size_t file_size = get_file_size(file_path);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(file_size > CHUNK_SIZE ? CHUNK_SIZE : file_size);
    CHECK((buffer != NULL ? 0 : -1), "Memory allocation failed", fclose(file), 1, process);

    size_t bytes_read, read_size = (file_size > CHUNK_SIZE ? CHUNK_SIZE : file_size);
    uint64_t total_read = 0;

    do{
        bytes_read = fread(buffer, 1, read_size, file);
        write_data(sockfd, buffer, bytes_read, server);
        total_read += bytes_read;
    }while(total_read < file_size);

    CHECK((bytes_read = ferror(file)) ? -1 : 0, "Error readijng file", (void)0, ACCEPTABLE_ERROR, process);
    if(bytes_read){
        free(buffer);
        return 0;
    }
    else{
        *filecontent = buffer;
        return total_read;
    }
}

size_t send_file(int sockfd, const char *file_path) {
    int fd = open(file_path, O_RDONLY);
    CHECK((fd != -1 ? 0 : -1), "Error opening file", /* cleanup */ , 1, process);

    size_t file_size = get_file_size(file_path); // Assuming `get_file_size` uses fstat for size calculation
    unsigned char *buffer = malloc(file_size > CHUNK_SIZE ? CHUNK_SIZE : file_size);
    CHECK((buffer != NULL ? 0 : -1), "Memory allocation failed", close(fd), 1, process);

    size_t bytes_read, read_size = (file_size > CHUNK_SIZE ? CHUNK_SIZE : file_size);
    uint64_t total_read = 0;


    do {
        bytes_read = read(fd, buffer, read_size);
        CHECK((bytes_read >= 0 ? 0 : -1), "Error reading file", free(buffer); close(fd), 1, process);

        if (bytes_read > 0) {
            write_data(sockfd, buffer, bytes_read, server);
            total_read += bytes_read;
        }
    } while (total_read < file_size && bytes_read > 0);

    close(fd);
    free(buffer);

    if (bytes_read < 0) { // Handle any read errors
        return 0;

    return total_read;
}

// Function to save a large buffer to a file in chunks
size_t recv_file(const char *file_path, const unsigned char *buffer, uint64_t size) {
    FILE *file = fopen(file_path, "wb");
    CHECK((file != NULL ? 0 : -1), "Error opening file", /* cleanup */ , 1, process);

    uint64_t bytes_written = 0;

    while (bytes_written < size) {
        size_t chunk = (size - bytes_written > CHUNK_SIZE) ? CHUNK_SIZE : (size - bytes_written);
        size_t written = fwrite(buffer + bytes_written, 1, chunk, file);
        if (written != chunk) {
            ERROR_AT();
            perror("Error writing to file");
            fclose(file);
            return -1;
        }
        bytes_written += written;
    }

    printf("Finished writing to file '%s'. Total bytes written: %llu\n", file_path, bytes_written);
    fclose(file);
    return 0;
}
