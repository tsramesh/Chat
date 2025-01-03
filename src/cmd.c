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

// void handle_command(int client_fd,  char *command, unsigned char *data, size_t data_len) {
void *handle_command(void *in) {
    command *c = (command *)in;
    char *cmd = c->string; cmd[4] = '\0';
    unsigned char *data = (unsigned char *)(c->string + 5);
    int data_len = strlen((char *)data);
    int sockfd = c->sockfd;
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "handle_command: %s, Remaining: %s", cmd, data);
    
    if (strncmp(cmd, "CHAT", 4) == 0) {
        handle_chat(sockfd, data, data_len);
    } else if (strncmp(cmd, "FILE", 4) == 0) {
        handle_file(sockfd, data, data_len);
    } else if (strncmp(cmd, "CONF", 4) == 0) {
        handle_conf(sockfd, data, data_len);
    } else if (strncmp(cmd, "AUTH", 4) == 0) {
        handle_auth(sockfd, data, data_len);
    } else {
        ERROR_AT(process);
        fprintf(stderr, "Unknown command: %s\n", cmd);
    }
    return NULL;
}

void handle_file(int client_fd, unsigned char *data, size_t data_len) {
    char * space = strrchr((char *)data, ' '); space[0] = '\0';
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "handle_file command: %s", data);

    char *filename = (char *)data;
    char *filesize = filename + strlen(filename) + 1;
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "filename: %s, filesize: %s", filename, filesize);
    recv_file(client_fd, filename, atol(filesize));

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