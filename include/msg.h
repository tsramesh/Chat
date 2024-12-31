#ifndef MSG_H
#define MSG_H

#include "common.h"     // For CHECK macro
#include "crypt.h"      // For sha256, aes_encrypt, aes_decrypt
#include "zip.h"        // For compression functions


// Function to read data from a client socket
// Parameters:
//   client_fd - File descriptor of the client socket
//   buffer    - Pointer to a dynamically allocated buffer to store the received data
//   buffer_len - Pointer to a size_t to store the length of the received data
// Returns:
//   0 on success, -1 on failure
// int write_data(int client_fd, const unsigned char *buffer, size_t buffer_len, bool server_end);
int write_data(int sockfd, unsigned char *buffer, size_t buffer_len, bool server_end);

// Helper function
int write_all(int fd, unsigned char *data, size_t len);

// Function to write data to a client socket
// Parameters:
//   client_fd - File descriptor of the client socket
//   buffer    - Pointer to the data to send
//   buffer_len - Length of the data to send
// Returns:
//   0 on success, -1 on failure
int read_data(int client_fd, unsigned char **buffer, size_t *buffer_len, bool server_end);

// Helper function
int read_all(int fd, unsigned char *data, size_t len);

void get_socket_buffer_sizes(int sockfd);

size_t exchange_rsa_data(int sockfd, unsigned char **encrypted_data, size_t *encrypted_data_len, bool server_end);

#endif // MSG_H
