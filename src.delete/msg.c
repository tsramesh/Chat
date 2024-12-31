/**
 * @file sockmsg.c
 * @brief Network message handling, including encryption, compression, checksum, and scrambling.
 *
 * This file provides functions for reading and writing data over a network socket with added support
 * for checksum calculation, encryption, decompression, and scrambling to secure the data transfer.
 */

#include "msg.h"

// Define constants
#define CHKSUM_LEN SHA256_DIGEST_LENGTH /**< Length of the checksum (SHA-256 hash length). */
#define IV_LEN   SHA256_DIGEST_LENGTH/2 /**< Length of the Initialization Vector (IV) used for AES encryption. */

/**
 * @brief Sum of digits of a number.
 * 
 * This helper function calculates the sum of the digits of a given integer `n`.
 * For example, the sum of digits of `123` would return `6`.
 *
 * @param n The number whose digits are to be summed.
 * @return The sum of the digits of `n`.
 */
int sum_digits(int n) {
    int sum = 0;
    
    while (n != 0) {
        sum += n % 10;   // Add the rightmost digit to the sum
        n /= 10;         // Remove the rightmost digit
    }
    
    return sum;
}

/**
 * @brief Scramble the checksum by using the port number of the connection.
 * 
 * This function retrieves the local or peer address of the socket and scrambles the checksum
 * by XORing it with the sum of the digits of the port number. This adds an additional layer
 * of uniqueness to the checksum.
 *
 * @param sockfd The socket file descriptor.
 * @param data The data to be scrambled (in-place).
 * @param server_end Flag indicating whether the operation is for the server or client.
 * @return 0 if successful, or -1 if an error occurred.
 */
int scramble(int sockfd, unsigned char *data, bool server_end) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if(server_end){
        // Invoked if Poll APIs are invoked by a server
        CHECK(getpeername(sockfd, (struct sockaddr *)&addr, &addr_len), "Failed to get peer address", {return -1;}, ACCEPTABLE_ERROR, process);
    } else {
        // Invoked if Poll APIs are invoked by a client
        CHECK(getsockname(sockfd, (struct sockaddr *)&addr, &addr_len), "Failed to get client address", {return -1;}, ACCEPTABLE_ERROR, process);
    }
    
    uint16_t port = ntohs(addr.sin_port);
    port = sum_digits(port);  // Sum digits of the port number

    // Scramble the checksum by XORing with the port digits sum
    for (size_t i = 0; i < CHKSUM_LEN; i++) {
        data[i] ^= port;
    }
    
    return 0;
}

/**
 * @brief Helper function to write data in chunks.
 * 
 * This function ensures that all the data is written to the file descriptor, even if the write
 * call returns a partial result. It handles the case where the write operation doesn't complete in
 * a single call, ensuring that the entire message is sent.
 *
 * @param fd The file descriptor where data should be written.
 * @param data The data to be written.
 * @param len The length of the data to be written.
 * @return 0 if successful, or -1 if an error occurred.
 */
int write_all(int fd, const unsigned char *data, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t ret = write(fd, data + written, len - written);
        CHECK(ret, "Write failed", {return -1;}, ACCEPTABLE_ERROR, process);
        written += ret;
    }
    return written;
}

/**
 * @brief Main client data writing function with encryption and compression.
 * 
 * This function handles writing data to the server, including the following operations:
 * - Calculating a checksum (SHA-256) for the data.
 * - Optionally compressing the data if it reduces the size.
 * - Encrypting the data using AES encryption.
 * - Scrambling the checksum to hide it.
 * - Sending the checksum and encrypted data to the server.
 *
 * @param client_fd The client file descriptor.
 * @param buffer The data to be sent.
 * @param buffer_len The length of the data to be sent.
 * @param server_end Flag indicating whether the operation is for the server or client.
 * @return 0 if successful, or -1 if an error occurred.
 */
int write_data(int sockfd, const unsigned char *buffer, size_t buffer_len, bool server_end) {
    if (!buffer_len || buffer == NULL) return 0;

    unsigned char *compressed_data = NULL; size_t compressed_len = 0;
    if (!compress_data(buffer, buffer_len, &compressed_data, &compressed_len) || compressed_len > buffer_len) {
        compressed_len = buffer_len; // Revert to original size if compression is ineffective
        free(compressed_data);
        compressed_data = (unsigned char *)buffer;
    }

    unsigned char *encrypted_data = malloc(compressed_len), checksum[SHA256_DIGEST_LENGTH]; size_t encrypted_data_len = 0;
    //cipher(compressed_data, compressed_len, checksum, &encrypted_data, &encrypted_data_len, 1); //1: Encrypt data; 0: Decrypt data
    aes_encrypt(compressed_data, compressed_len, checksum, encrypted_data, &encrypted_data_len);

    uint32_t encrypted_data_nw_len = htonl(encrypted_data_len);
    if(compressed_data != buffer) free(compressed_data);
printf("Step-1 - %zu\n", encrypted_data_len);
for (int i = 0; i < encrypted_data_len; i++) {
    printf("%02x", encrypted_data[i]);
}
printf("\n");

    char *public_key = server ? endpoint_public.key : client_public.key;
    unsigned char *encrypted_checksum = 0; size_t encrypted_checksum_len = 0;
    rsa_encrypt_with_public_key(public_key, checksum, SHA256_DIGEST_LENGTH, &encrypted_checksum, &encrypted_checksum_len);
    uint32_t encrypted_checksum_nw_len = htonl(encrypted_checksum_len);
printf("Step-2 - %zu\n", encrypted_checksum_len);

    size_t transmission_len = sizeof(uint32_t) + encrypted_checksum_len + sizeof(uint32_t) + encrypted_data_len;
    unsigned char * transmission_payload = malloc(transmission_len);
printf("Step-3 - %zu\n", transmission_len);

    size_t offset = 0;
    memcpy( transmission_payload + offset, &encrypted_checksum_nw_len, sizeof(uint32_t) ); offset += sizeof(uint32_t);
    memcpy( transmission_payload + offset, encrypted_checksum, encrypted_checksum_len );   offset += encrypted_checksum_len;
    memcpy( transmission_payload + offset, &encrypted_data_nw_len, sizeof(uint32_t) );     offset += sizeof(uint32_t);
    memcpy( transmission_payload + offset, &encrypted_data, encrypted_data_len );          offset += encrypted_data_len;

    // Send the complete buffer
    if ( write_all(sockfd, transmission_payload, transmission_len) != transmission_len )
        printf("Not all data was written to the destination");

    free(encrypted_checksum);
    free(encrypted_data);
    free(transmission_payload);
    return 0;
}

/**
 * @brief Helper function to read data in one go.
 * 
 * This function ensures that all the requested data is read from the file descriptor. It handles
 * partial reads and ensures that the entire data is received in the buffer.
 *
 * @param fd The file descriptor to read data from.
 * @param data The buffer to store the received data.
 * @param len The length of the data to be read.
 * @return The total number of bytes read, or a negative value if an error occurred.
 */
int read_all(int fd, unsigned char *data, size_t len) {
    ssize_t total_read = 0;
    while (total_read < len) {
        ssize_t ret = read(fd, data + total_read, len - total_read);
        if (ret <= 0) return ret;  // Return if there was an error or EOF
        total_read += ret;
    }
    return total_read;
}

/**
 * @brief Main client data reading function with decryption, decompression, and checksum verification.
 * 
 * This function handles reading data from the server, including the following operations:
 * - Reading the length of the incoming payload.
 * - Reading the encrypted payload.
 * - Decrypting the payload using AES decryption.
 * - Attempting to decompress the data.
 * - Verifying the checksum.
 *
 * @param client_fd The client file descriptor.
 * @param buffer Pointer to the buffer where the received data will be stored.
 * @param buffer_len Pointer to store the length of the decompressed data.
 * @param server_end Flag indicating whether the operation is for the server or client.
 * @return 0 if successful, or -1 if an error occurred.
 */
int read_data(int sockfd, unsigned char **buffer, size_t *buffer_len, bool server_end) {

    unsigned char *encrypted_checksum = 0; size_t encrypted_checksum_len = 0;
    if(read_all(sockfd, (unsigned char *)&encrypted_checksum_len, sizeof(uint32_t)) != sizeof(uint32_t)) return 0;
    encrypted_checksum_len = ntohl(encrypted_checksum_len);
printf("Step-1 - %zu\n", encrypted_checksum_len);
    
    encrypted_checksum = malloc(encrypted_checksum_len);
    if(read_all(sockfd, encrypted_checksum, encrypted_checksum_len) != encrypted_checksum_len) return 0;
printf("Step-2\n");

    char *private_key = server ? client_private.key : endpoint_private.key;
    unsigned char *checksum = 0; size_t checksum_len = 0;
    rsa_decrypt_with_private_key(private_key, encrypted_checksum, encrypted_checksum_len, &checksum, &checksum_len);
printf("Step-3\n");
    free(encrypted_checksum);

    unsigned char *encrypted_data = 0; size_t encrypted_data_len = 0;
    if(read_all(sockfd, (unsigned char *)&encrypted_data_len, sizeof(uint32_t)) != sizeof(uint32_t)) return 0;
    encrypted_data_len = ntohl(encrypted_data_len);
printf("Step-4 - %zu\n", encrypted_data_len);

    encrypted_data = malloc(encrypted_data_len);
    if(read_all(sockfd, encrypted_data, encrypted_data_len) != encrypted_data_len) return 0;
printf("Step-5 - %zu\n", encrypted_data_len);
for (int i = 0; i < encrypted_data_len; i++) {
    printf("%02x", encrypted_data[i]);
}
printf("\n");

    unsigned char *decrypted_data = malloc(encrypted_data_len); size_t decrypted_data_len = 0;
    //if(cipher(encrypted_data, encrypted_data_len, checksum, &decrypted_data, &decrypted_data_len, 0) == -1) return 0;
    aes_decrypt(encrypted_data, encrypted_data_len, checksum, decrypted_data, &decrypted_data_len);
    free(encrypted_data);
printf("Step-6 - %zu : %s\n", decrypted_data_len, decrypted_data);

    unsigned char *decompressed_data = 0; size_t decompressed_data_len = 0;
    decompress_data( decrypted_data, decrypted_data_len, &decompressed_data, &decompressed_data_len);
    free(decrypted_data);
printf("Step-7 - %zu : %s\n", decompressed_data_len, decompressed_data);

    unsigned char calculated_checksum[CHKSUM_LEN];
    sha256(decompressed_data, decompressed_data_len, calculated_checksum);
printf("Step-8\n");
    if( !memcmp(checksum, calculated_checksum, CHKSUM_LEN) )
        printf("Data integrity check (Checksum match failed)\n");

    free(checksum);
    *buffer = decompressed_data;
    *buffer_len = decompressed_data_len;
    return 0;
}


void get_socket_buffer_sizes(int sockfd) {
    int optval;
    socklen_t optlen = sizeof(optval);

    // Get the receive buffer size
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &optval, &optlen) == -1) {
        perror("getsockopt SO_RCVBUF");
        exit(EXIT_FAILURE);
    }
    printf("Receive buffer size: %d bytes\n", optval);

    // Get the transmit buffer size
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) == -1) {
        perror("getsockopt SO_SNDBUF");
        exit(EXIT_FAILURE);
    }
    printf("Transmit buffer size: %d bytes\n", optval);
}

size_t exchange_rsa_data(int sockfd, unsigned char **encrypted_data, size_t *encrypted_data_len, bool server_end) {
    if(server_end){
        if (read(sockfd, encrypted_data_len, sizeof(uint32_t)) != sizeof(uint32_t)) 
            return -1; // Failed to read size

        // Convert size from network byte order to host byte order
        *encrypted_data_len = ntohl(*encrypted_data_len);

        // Allocate buffer to read the entire encrypted payload
        *encrypted_data = malloc(*encrypted_data_len);
        if (!(*encrypted_data)) return -1;

        // Read the entire encrypted payload
        if (read(sockfd, *encrypted_data, *encrypted_data_len) != (ssize_t)(*encrypted_data_len)) {
            free(*encrypted_data);
            printf("Failed to read encrypted data\n");
            return -1; // Failed to read encrypted data
        }
        printf("Successfully read encrypted data\n");
        return *encrypted_data_len;
    } else {

        // Prepend the size of the encrypted data (network byte order)
        uint32_t network_size = htonl(*encrypted_data_len);

        // Write the entire payload (size + encrypted data) in one call
        if (write(sockfd, &network_size, sizeof(uint32_t)) != sizeof(uint32_t)) {
            return -1; // Failed to send data
        }

        // Write the entire payload (size + encrypted data) in one call
        if (write(sockfd, *encrypted_data, (*encrypted_data_len)) != (ssize_t)(*encrypted_data_len)) {
            return -1; // Failed to send data
        }
        return (*encrypted_data_len);
    }
    return 0;
}