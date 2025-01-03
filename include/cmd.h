#ifndef CMD_H
#define CMD_H

#include "common.h"
#include "msg.h"
#include "file.h"

typedef struct {
    int sockfd;
    char *string;
} command;

void *handle_command(void *in);
void handle_chat(int sockfd, unsigned char *data, size_t data_len);
void handle_file(int sockfd, unsigned char *data, size_t data_len);
void handle_conf(int sockfd, unsigned char *data, size_t data_len);
void handle_auth(int sockfd, unsigned char *data, size_t data_len);
void extract_command(unsigned char *buffer, char *command, unsigned char **data, size_t *data_len);
void broadcast_message(unsigned char *message, size_t message_len, int sender_fd, int *client_fds, size_t num_clients);

#endif // CMD_H
