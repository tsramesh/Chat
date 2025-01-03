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
int write_all(int fd, unsigned char *data, size_t len) {
    // Entry logging: Log the start of the write_all function
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "write_all function started. Writing %zu bytes to file descriptor %d", len, fd);

    size_t written = 0, ret = 0;

    // Step 1: Write the data in chunks until all data is written
    while (written < len) {
        ret = 0;
        ret = write(fd, data + written, len - written);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Written: %zu, ret: %zu, len: %zu", written, ret, len);

        // Log each write operation and check if it succeeded
        if (ret < 0) {
            // Log the error if write fails
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Write failed for %zu bytes at position %zu. Error: %s", len - written, written, strerror(errno));
        }

        // Update the amount of written data and log the progress
        written += ret;
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Written %zu bytes so far, total written: %zu", ret, written);
    }

    // Exit logging: Log successful completion of the write_all function
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "write_all function completed successfully. Total bytes written: %zu", written);

    // Return the total number of bytes written
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
int write_data(int sockfd, unsigned char *buffer, size_t buffer_len, bool server_end) {
    // Entry logging: Log the start of the write_data function
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "write_data function started. Writing %zu bytes to socket %d", buffer_len, sockfd);

    // If buffer length is 0, no data to write, return early
    if (!buffer_len) {
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Buffer length is 0, nothing to write.");
        return 0;
    }

    // Step-1: Calculate checksum using sha256 function
    unsigned char checksum[CHKSUM_LEN];
    sha256(buffer, buffer_len, checksum);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Checksum calculated for buffer.");

    // Step-2: Compress the data if possible, and choose the better option (compressed or uncompressed)
    unsigned char *compressed_data = NULL; 
    size_t compressed_len = 0;
    if (compress_data(buffer, buffer_len, &compressed_data, &compressed_len) || compressed_len >= buffer_len) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Compression failed or didn't save space, using original data.");
        if (compressed_data) free(compressed_data);
        compressed_data = buffer;
        compressed_len = buffer_len;
    } else {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Data compressed successfully. Compressed length: %zu", compressed_len);
    }

    // Step-3: Encrypt compressed data using cipher function with checksum as the key & IV
    unsigned char *encrypted_data = NULL; 
    size_t encrypted_len = 0;
    if (cipher(compressed_data, compressed_len, checksum, &encrypted_data, &encrypted_len, ENCRYPT)) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Encryption failed.");
        if (compressed_data != buffer) free(compressed_data);
        return 0;
    } else {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Data encrypted successfully. Encrypted length: %zu", encrypted_len);
        if (compressed_data != buffer) free(compressed_data);
    }

    // Step 4: Encrypt the checksum using the appropriate RSA public key (server or client)
    unsigned char *encrypted_checksum = NULL;
    size_t encrypted_checksum_len = 0;
    char *public_key = server_end ? endpoint_public.key : client_public.key;
    if (rsa_encrypt_with_public_key(public_key, checksum, SHA256_DIGEST_LENGTH, &encrypted_checksum, &encrypted_checksum_len)) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "RSA encryption of checksum failed.");
        free(encrypted_data);
        return 0;
    } else {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Checksum encrypted successfully. Encrypted checksum length: %zu", encrypted_checksum_len);
    }

    size_t total_written = 0;

    // Step 5: Write the encrypted checksum length, encrypted checksum, encrypted data, and encrypted length to the socket
    uint32_t encrypted_checksum_len_htonl = htonl(encrypted_checksum_len);
    if (write_all(sockfd, (unsigned char *)&encrypted_checksum_len_htonl, sizeof(uint32_t)) == sizeof(uint32_t)) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Encrypted checksum length sent to socket.");
    } else {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to write encrypted checksum length to socket.");
        return 0;
    }

    // Step-6: I transmit the encrypted checksum
    if (write_all(sockfd, encrypted_checksum, encrypted_checksum_len) == encrypted_checksum_len) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Encrypted checksum data sent to socket.");
    } else {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to write encrypted checksum to socket.");
        return 0;
    }

    // Step-7: I transmit the cipher function returned encrypted payload length in network byte order
    uint32_t encrypted_len_htonl = htonl(encrypted_len);
    if (write_all(sockfd, (unsigned char *)&encrypted_len_htonl, sizeof(uint32_t)) == sizeof(uint32_t)) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Encrypted data length sent to socket.");
    } else {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to write encrypted data length to socket.");
        return 0;
    }

    // Step-8: Finally i transmit the cipher function returned encrypted payload
    if (write_all(sockfd, encrypted_data, encrypted_len) == encrypted_len) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Encrypted data sent to socket.");
        total_written = (sizeof(uint32_t) * 2) + encrypted_checksum_len + encrypted_len;
    } else {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to write encrypted data to socket.");
        return 0;
    }

    // Step 6: Free allocated resources
    free(encrypted_checksum);
    free(encrypted_data);

    // Exit logging: Log the completion of the write_data function
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "write_data function completed. Total bytes written: %zu", total_written);

    return total_written;
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
    // Entry logging: Log the start of the read_all function
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "read_all function started. Reading %zu bytes from file descriptor %d", len, fd);

    ssize_t total_read = 0;

    // Step 1: Read data in chunks until the specified length is reached
    while (total_read < len) {
        ssize_t ret = read(fd, data + total_read, len - total_read);

        // Step 2: Handle error or EOF by checking the return value of read()
        if (ret <= 0) {
            if (ret == 0) {
                // Log EOF condition
                log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "End of file reached on file descriptor %d", fd);
            } else {
                // Log error condition
                log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Error occurred while reading from file descriptor %d. Error code: %zd", fd, ret);
            }
            return ret;  // Return the error code or 0 (EOF)
        }

        // Step 3: Update total read count
        total_read += ret;
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Read %zd bytes, total read so far: %zd bytes", ret, total_read);
    }

    // Step 4: Log the successful completion of the read operation
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "read_all function completed. Total bytes read: %zd", total_read);

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
    // Entry logging: Log the start of the read_data function
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "read_data function started. Reading data from socket %d", sockfd);

    uint32_t encrypted_checksum_len_ntohl = 0; 
    size_t encrypted_checksum_len = 0;

    // Step 1: Read the encrypted checksum length from the socket
    if (!read_all(sockfd, (unsigned char *)&encrypted_checksum_len_ntohl, sizeof(uint32_t)) ||
        !(encrypted_checksum_len = ntohl(encrypted_checksum_len_ntohl))) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to read encrypted checksum length from socket %d", sockfd);
        return 0; // Error occurred or invalid checksum length
    }

    // Step 2: Allocate memory for encrypted checksum and read it from the socket
    unsigned char *encrypted_checksum = malloc(encrypted_checksum_len);
    if (read_all(sockfd, encrypted_checksum, encrypted_checksum_len) != encrypted_checksum_len) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to read encrypted checksum from socket %d", sockfd);
        free(encrypted_checksum);
        return 0; // Failed to read the full checksum
    }

    // Step 3: Decrypt the checksum using the private key
    unsigned char *decrypted_checksum = 0; 
    size_t decrypted_checksum_len = 0;
    char *private_key = server_end ? client_private.key : endpoint_private.key;
    if (rsa_decrypt_with_private_key(private_key, encrypted_checksum, encrypted_checksum_len, &decrypted_checksum, &decrypted_checksum_len)) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Checksum decryption failed");
        free(encrypted_checksum);
        return 0; // Decryption failed
    }
    free(encrypted_checksum);

    // Step 4: Read encrypted data length from socket
    uint32_t encrypted_data_len_ntohl = 0;
    if (read_all(sockfd, (unsigned char *)&encrypted_data_len_ntohl, sizeof(uint32_t)) != sizeof(uint32_t)) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to read encrypted data length from socket %d", sockfd);
        free(decrypted_checksum);
        return 0;
    }
    size_t encrypted_data_len = ntohl(encrypted_data_len_ntohl);

    // Step 5: Allocate memory for encrypted data and read it from the socket
    unsigned char *encrypted_data = malloc(encrypted_data_len);
    if (read_all(sockfd, encrypted_data, encrypted_data_len) != encrypted_data_len) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to read encrypted data from socket %d", sockfd);
        free(encrypted_data);
        free(decrypted_checksum);
        return 0; // Failed to read the full data
    }

    // Step 6: Decrypt the data using the decrypted checksum
    unsigned char *decrypted_data = 0; 
    size_t decrypted_data_len = 0;
    if (cipher(encrypted_data, encrypted_data_len, decrypted_checksum, &decrypted_data, &decrypted_data_len, DECRYPT)) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Data decryption failed for socket %d", sockfd);
        free(encrypted_data);
        free(decrypted_checksum);
        return 0; // Decryption failed
    }
    free(encrypted_data);

    // Step 7: Decompress the data
    unsigned char *decompressed_data = 0; 
    size_t decompressed_data_len = 0;
    if (decompress_data(decrypted_data, decrypted_data_len, &decompressed_data, &decompressed_data_len)) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Data decompression failed for socket %d", sockfd);
        free(decrypted_checksum);
        free(decrypted_data);
        return 0; // Decompression failed
    }

    // Step 8: Free memory for decrypted data if it's not used
    if (decompressed_data != decrypted_data) {
        free(decrypted_data);
    }

    // Step 9: Verify the checksum of the decompressed data
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    sha256(decompressed_data, decompressed_data_len, checksum);
    if (memcmp(checksum, decrypted_checksum, SHA256_DIGEST_LENGTH)) {
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Checksum mismatch for decompressed data received from socket %d", sockfd);
        printf("Checksum for data transmitted did not match source!\n");
    }

    // Step 10: Set the output buffer and buffer length
    *buffer = decompressed_data;
    *buffer_len = decompressed_data_len;

    // Exit logging: Log the successful completion of the read_data function
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "read_data function completed. Total bytes read: %zu", *buffer_len);

    return *buffer_len; // Return the length of the decompressed data
}


void get_socket_buffer_sizes(int sockfd) {
    // Logging entry: Log the start of the function and the socket file descriptor
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "get_socket_buffer_sizes function started. Getting buffer sizes for socket %d", sockfd);

    int optval;
    socklen_t optlen = sizeof(optval);

    // Step 1: Get the receive buffer size
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &optval, &optlen) == -1) {
        // Log error on failure to get receive buffer size
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to get receive buffer size for socket %d", sockfd);
        perror("getsockopt SO_RCVBUF");
        return; // Exit if unable to fetch buffer size
    }
    
    // Log the received buffer size
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Receive buffer size for socket %d: %d bytes", sockfd, optval);
    printf("Receive buffer size: %d bytes\n", optval);

    // Step 2: Get the transmit buffer size
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) == -1) {
        // Log error on failure to get transmit buffer size
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to get transmit buffer size for socket %d", sockfd);
        perror("getsockopt SO_SNDBUF");
        return; // Exit if unable to fetch buffer size
    }

    // Log the transmit buffer size
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Transmit buffer size for socket %d: %d bytes", sockfd, optval);
    printf("Transmit buffer size: %d bytes\n", optval);

    // Logging exit: Log that the function has completed successfully
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "get_socket_buffer_sizes function completed successfully for socket %d", sockfd);
}

size_t exchange_rsa_data(int sockfd, unsigned char **encrypted_data, size_t *encrypted_data_len, bool server_end) {
    // Logging entry: Log the start of the function, indicating the RSA exchange attempt.
    log_message(LOG_CRITICAL, process, __func__, __FILE__, __LINE__, "Attempting to exchange RSA keys between peers...");

    if (server_end) {
        // Server side: Read the size of the encrypted data (from the client)
        if (read(sockfd, encrypted_data_len, sizeof(uint32_t)) != sizeof(uint32_t)) {
            // Log failure to read data length from socket
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to read encrypted data size from socket.");
            return -1; // Failed to read size
        }

        // Convert size from network byte order to host byte order
        *encrypted_data_len = ntohl(*encrypted_data_len);

        // Log the size of the encrypted data received from the client
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Received encrypted data size: %zu bytes", *encrypted_data_len);

        // Allocate buffer to read the entire encrypted payload
        *encrypted_data = malloc(*encrypted_data_len);
        if (!(*encrypted_data)) {
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Memory allocation failed for encrypted data buffer.");
            return -1; // Memory allocation failure
        }

        // Read the entire encrypted payload from the client
        if (read(sockfd, *encrypted_data, *encrypted_data_len) != (ssize_t)(*encrypted_data_len)) {
            // Log failure to read the actual encrypted data
            free(*encrypted_data);
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to read encrypted data from socket.");
            printf("Failed to read encrypted data\n");
            return -1; // Failed to read encrypted data
        }

        // Log success after reading encrypted data
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully read encrypted data from client.");

        return *encrypted_data_len; // Return the length of the received encrypted data
    } else {
        // Client side: Prepend the size of the encrypted data (network byte order)
        uint32_t network_size = htonl(*encrypted_data_len);

        // Log the size of data being sent to the server
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Sending encrypted data of size: %zu bytes", *encrypted_data_len);

        // Write the size of the encrypted data to the server
        if (write(sockfd, &network_size, sizeof(uint32_t)) != sizeof(uint32_t)) {
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to send encrypted data size to server.");
            return -1; // Failed to send data size
        }

        // Write the entire encrypted payload to the server
        if (write(sockfd, *encrypted_data, (*encrypted_data_len)) != (ssize_t)(*encrypted_data_len)) {
            log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to send encrypted data to server.");
            return -1; // Failed to send data
        }

        // Log success after sending encrypted data
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully sent encrypted data to server.");

        return (*encrypted_data_len); // Return the length of the sent encrypted data
    }

    return 0; // Default return value (unreachable)
}
