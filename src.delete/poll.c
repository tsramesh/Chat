/**
 * @file poll_implementation.c
 * @brief Implementation of cross-platform event polling functions for server-client communication.
 *
 * This file provides functionality for handling non-blocking sockets, accepting new client connections,
 * processing client data, managing events, and running the main polling loop.
 */

#include "poll.h"

// Variable to hold server socket descriptor
int server_fd = 0;

// Process ID markers
int cpid = 0; // Stores child process ID
int ppid = 0; // Stores parent process ID 

// 'Parent' or 'Child' indicator
char * process = NULL;

// Variable to hold all connections to this server instance
ClientManager *manager = 0;

// Buffer for RSA Keys
char * p_public_key  = NULL;  // Parent process public key
char * p_private_key = NULL;  // Parent process private key
char * c_public_key  = NULL;  // Child process public key
char * c_private_key = NULL;  // Child process private key
char * e_public_key  = NULL;  // End point process public key
char * e_private_key = NULL;  // End point process private key



/**
 * Sets up the server socket:
 * 1. Creates a socket.
 * 2. Binds the socket to the specified port and address.
 * 3. Listens for incoming client connections.
 *
 * @return The file descriptor for the created server socket.
 * Exits the program if any operation fails.
 */
int setup_server_socket(int port) {
    int sockfd = 0; // File descriptor for the server socket

    // Address structure to bind the socket
    struct sockaddr_in address = {
        .sin_family = AF_INET,        // Use IPv4
        .sin_addr.s_addr = INADDR_ANY, // Accept connections on all network interfaces
        .sin_port = htons(port)       // Convert the port to network byte order
    };

    // Step 1: Create the server socket
    CHECK(sockfd = socket(AF_INET, SOCK_STREAM, 0), "Socket creation failed", (void)0, CRITICAL_ERROR, process);

    // Step 2: Bind the socket to the specified address and port
    CHECK(bind(sockfd, (struct sockaddr *)&address, sizeof(address)), "Bind failed", (void)0, CRITICAL_ERROR, process);

    // Step 3: Start listening for incoming connections
    CHECK(listen(sockfd, BACKLOG), "Listen failed", (void)0, CRITICAL_ERROR, process);

    // Log success and return the server socket descriptor
    printf("Server listening on port %d...\n", PORT);
    return sockfd;
}




/**
 * @brief Sets a socket to non-blocking mode.
 *
 * @param socket_fd The file descriptor of the socket.
 * @return 0 on success, or terminates the program on error.
 */
int set_non_blocking(int socket_fd) {
    int flags = fcntl(socket_fd, F_GETFL, 0);
    CHECK(flags, "fcntl(F_GETFL) failed", (void)0, CRITICAL_ERROR, process);
    CHECK(fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK), "fcntl(F_SETFL) failed", (void)0, CRITICAL_ERROR, process);
    return 0;
}




/**
 * @brief Accepts a new client connection and spawns a dedicated thread for that client.
 *
 * @param poll_fd The file descriptor of the poll instance.
 * @param sockfd The listening socket file descriptor.
 */
int poll_newconn() {
    struct sockaddr_in client_address;
    socklen_t client_len = sizeof(client_address);

    int sockfd = accept(server_fd, (struct sockaddr *)&client_address, &client_len);
    CHECK(sockfd, "Accept failed", (void)0, CRITICAL_ERROR, process);

    // Create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Error occurred
        perror("Fork failed");
        return -1;
    } else if (pid == 0) {
        // Child process
        ppid = getppid(); cpid = getpid();
        printf("New client with child process %d successfully connected\n", cpid);

        generate_rsa_key_pair_4096(&client_public.key, &client_public.len, &client_private.key, &client_private.len);

        exchange_public_keys( sockfd, client_public.key, client_public.len, client_private.key, &endpoint_public.key, &endpoint_public.len, server);

        printf("Exchanged keys:\n%s\n%s\n", client_public.key, endpoint_public.key);
        if(process) free(process);
        process = fstring("%s-%d", "Child", cpid);

        // Close the server socket
        close(server_fd);
        server_fd = 0;
        cleanup_client_manager(manager);

        // Set the client socket to non-blocking mode
        set_non_blocking(sockfd);

        poll_loop((void *)&sockfd);
    } else {
        // Parent process
        // Close child socket descriptor
        close(sockfd);
    }

    // Add the new connection to the client list
    add_client(manager, sockfd, client_address);

    return sockfd;
}




/**
 * @brief Reads and handles data from an existing client.
 *
 * @param poll_fd The file descriptor of the poll instance.
 * @param sockfd The file descriptor of the client socket.
 */
void poll_data(int poll_fd, int sockfd) {
    unsigned char *buffer = 0;
    size_t bytes_read = 0;

    // Read data from the client using a custom API
    read_data(sockfd, &buffer, &bytes_read, server);

    if (bytes_read <= 0) {
        // Client disconnected or encountered an error
        printf("Client %d disconnected\n", cpid);
        REMOVE_FROM_POLL(poll_fd, sockfd);
        close(sockfd);
        Alive = 0;
    } else {
        // Print the received data
        printf("%s-> : %s\n", process, buffer);

        // Free the memory allocated by the `read_data` function
        free(buffer);
    }
}




/**
 * @brief Processes events triggered on the poll instance.
 *
 * @param poll_fd The file descriptor of the poll instance.
 * @param events Pointer to the array of events.
 * @param num_events Number of events in the array.
 * @param sockfd The file descriptor of the listening socket.
 */
// void poll_events(int poll_fd, void* events, int num_events, int sockfd) {
void poll_events(int poll_fd, void* events, int num_events) {
    for (int i = 0; i < num_events; ++i) {
        int fd = EVENT_FD(&((EVENT_STRUCT*)events)[i]);
        if (EVENT_IN(&((EVENT_STRUCT*)events)[i])) {
            if (fd == server_fd && server) {
                poll_newconn(); // Handle new client connection
            } else {
                poll_data(poll_fd, fd); // Handle data from an existing client
            }
        }
    }
}




/**
 * @brief The main polling loop that manages connections and events.
 *
 * This function runs in a loop to handle client connections and data transfer
 * using the poll mechanism. It dynamically adjusts the size of the event array
 * based on the number of events processed.
 *
 * @param fd Pointer to the file descriptor of the listening socket.
 * @return NULL when the loop exits.
 */
void* poll_loop(void * fd) {
    // Set up the poll instance
    int poll_fd = SETUP_POLL(process);

    int max_events = INIT_EVENT_SIZE;
    EVENT_STRUCT* events = malloc(max_events * sizeof(EVENT_STRUCT));
    CHECK(!events ? -1 : 0, "Events array could not be allocated", (void)0, CRITICAL_ERROR, process);

    int sockfd = *(int *)fd;

    // Add the listening socket to the poll
    ADD_TO_POLL(poll_fd, sockfd);

    // Initiate the client manager link list
    manager = initialize_client_manager();

    // Polling loop
    while (Alive) {
        // Wait for events
        int num_events = WAIT_FOR_EVENTS(poll_fd, events, max_events, process);
        if(num_events < 0)exit(0);

        // Process the events
        poll_events(poll_fd, events, num_events);

        // Dynamically resize the event array if it is full
        if (num_events == max_events) {
            max_events *= 2;
            events = realloc(events, max_events * sizeof(EVENT_STRUCT));
            CHECK(!events ? -1 : 0, "Events array could not be expanded", (void)0, CRITICAL_ERROR, process);
        }
    }

    // Cleanup
    free(events);
    close(poll_fd);
    return NULL;
}




/**
 * Exchanges public keys between the client and the server.
 * 
 * @param client_fd         File descriptor of the socket connection.
 * @param my_public_key     PEM-encoded public key of the sender (client/server).
 * @param my_public_key_len Length of the sender's public key.
 * @param their_public_key  Pointer to store the received public key.
 *                          Dynamically allocated; caller must free.
 * @param their_public_key_len Pointer to store the length of the received public key.
 * @param server_end        Boolean indicating if the caller is the server (`true`) or client (`false`).
 *
 * @return 0 on success, -1 on failure.
 */
int exchange_public_keys(int sockfd, const char *my_public_key, size_t my_public_key_len, const char *my_private_key, char **their_public_key, size_t *their_public_key_len, bool server_end) {
    int ret = -1;
    unsigned char *data = 0;
    size_t data_len = 0;

    if (server_end) { // Server-side logic
        data = malloc(my_public_key_len + sizeof(uint32_t));
        data_len = htonl(my_public_key_len);
        memcpy(data, &data_len, sizeof(uint32_t));
        memcpy(data + sizeof(uint32_t), my_public_key, my_public_key_len);
        write(sockfd, data, my_public_key_len + sizeof(uint32_t));
        free(data);

        exchange_rsa_data(sockfd, &data, &data_len, server);
        rsa_decrypt_with_private_key(my_private_key, data, data_len, (unsigned char **)their_public_key, their_public_key_len);
    } else {  // Step 3: Client-side logic
        read(sockfd, &data_len, sizeof(uint32_t));
        *their_public_key_len = ntohl(data_len);
        *their_public_key = malloc(*their_public_key_len);
        read(sockfd, *their_public_key, *their_public_key_len);
        
        rsa_encrypt_with_public_key(*their_public_key, (const unsigned char *)my_public_key, my_public_key_len, &data, &data_len);
        exchange_rsa_data(sockfd, &data, &data_len, server);
    }
    free(data);

    return ret;
}