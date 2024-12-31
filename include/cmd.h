#ifndef CMD_H
#define CMD_H

#include "common.h"
#include "msg.h"

typedef struct {
    char *buffer;
    size_t size;
} FileContent;

void handle_command(int client_fd, char *command, unsigned char *data, size_t data_len);
void handle_chat(int client_fd, unsigned char *data, size_t data_len);
void handle_file(int client_fd, unsigned char *data, size_t data_len);
void handle_conf(int client_fd, unsigned char *data, size_t data_len);
void handle_auth(int client_fd, unsigned char *data, size_t data_len);
void extract_command(unsigned char *buffer, char *command, unsigned char **data, size_t *data_len);
void broadcast_message(unsigned char *message, size_t message_len, int sender_fd, int *client_fds, size_t num_clients);
FileContent *readFile(char *path);

#endif // CMD_H
