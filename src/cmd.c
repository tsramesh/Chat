#include "cmd.h"

void extract_command( unsigned char *buffer, char *command, unsigned char **data, size_t *data_len) {
    // Copy the first 4 bytes as the command
    memcpy(command, buffer, 4);
    command[4] = '\0';

    // Remaining data is the payload
    *data_len = strlen(( char *)(buffer + 4));
    *data = (unsigned char *)(buffer + 4);
}

void handle_chat(int client_fd, unsigned char *data, size_t data_len) {
    int target_fd = atoi(( char *)data); // Assuming the target client FD is sent
    unsigned char *message = data + sizeof(int); // Remaining data is the message

    if (write_data(target_fd, message, data_len - sizeof(int), false) < 0) {
        ERROR_AT(process);
        fprintf(stderr, "Failed to forward chat message\n");
    }
}

void handle_command(int client_fd,  char *command, unsigned char *data, size_t data_len) {
    if (strncmp(command, "CHAT", 4) == 0) {
        handle_chat(client_fd, data, data_len);
    } else if (strncmp(command, "FILE", 4) == 0) {
        handle_file(client_fd, data, data_len);
    } else if (strncmp(command, "CONF", 4) == 0) {
        handle_conf(client_fd, data, data_len);
    } else if (strncmp(command, "AUTH", 4) == 0) {
        handle_auth(client_fd, data, data_len);
    } else {
        ERROR_AT(process);
        fprintf(stderr, "Unknown command: %s\n", command);
    }
}

void handle_file(int client_fd, unsigned char *data, size_t data_len) {
    return;
}

void handle_conf(int client_fd, unsigned char *data, size_t data_len) {
    return;
}

void handle_auth(int client_fd, unsigned char *data, size_t data_len) {
    return;
}

void broadcast_message(unsigned char *message, size_t message_len, int sender_fd, int *client_fds, size_t num_clients) {
    return;
}

FileContent *readFile( char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);

    char *buffer = (char *)malloc(size);
    if (!buffer) {
        perror("malloc");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, size, file);
    fclose(file);

    FileContent *fileContent = (FileContent *)malloc(sizeof(FileContent));
    if (!fileContent) {
        perror("malloc");
        free(buffer);
        return NULL;
    }

    fileContent->buffer = buffer;
    fileContent->size = size;
    return fileContent;
}
