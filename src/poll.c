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
int server_port = 0;
char * server_ip;

// Process ID markers
int cpid; // Stores child process ID
int ppid; // Stores parent process ID 

// 'Parent' or 'Child' indicator
char * process;
char * config_file_path;

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
int setup_server_socket(int *port) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting setup_server_socket");
    int sockfd = 0; // File descriptor for the server socket

    char *interface = 0;
    get_active_network_interface(&interface, &server_ip);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "get_active_network_interface: Interface: %s, host: %s", interface, server_ip);

    // Step 1: Create the server socket    
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Server set up failed!: %s", errno, strerror(errno));
        exit(-1);
    }

    // Address structure to bind the socket
    struct sockaddr_in address = {
        .sin_family = AF_INET,        // Use IPv4
        .sin_port = htons(*port)       // Convert the port to network byte order
    };
    inet_pton(AF_INET, server_ip, &address.sin_addr); // Use the specific interface's IP
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Setting server port to %d", *port);

    // Step 2: Bind the socket to the specified address and port
    if ((bind(sockfd, (struct sockaddr *)&address, sizeof(address))) == -1) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Failed to bind socket to port %d on server %s: %s", errno, *port, server_ip, strerror(errno));
        exit(-1);
    }
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Socket bind on address %s successful", server_ip);

    if(! *port ) { 
        // Retrieve the assigned port number
        socklen_t addr_len = sizeof(address);
        if (getsockname(sockfd, (struct sockaddr *)&address, &addr_len) == -1){
            log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Could not retrieve the server port number: %s", errno, strerror(errno));
            exit(-1);
        }
        *port = ntohs(address.sin_port);
    }
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Socket bound to port %d on address %s successful", *port, server_ip);

    // Step 3: Start listening for incoming connections
    if (listen(sockfd, BACKLOG) == -1){
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Socket listen failed: %s", errno, strerror(errno));
        exit(-1);
    }
    // Log success and return the server socket descriptor
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Server listening on port %d at address %s... awaiting new connections", *port, server_ip);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed setup_server_socket() successfully");
    
    return sockfd;
}




/**
 * @brief Sets a socket to non-blocking mode.
 *
 * @param socket_fd The file descriptor of the socket.
 * @return 0 on success, or terminates the program on error.
 */
int set_non_blocking(int socket_fd) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting setup_server_socket");
    int flags = 0;
    
    if ((flags = fcntl(socket_fd, F_GETFL, 0)) == -1) {
        log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "ERR_%d: Call to fcntl failed: %s", errno, strerror(errno));
    }
    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "ERR_%d: Call to fcntl(F_SETFL) failed: %s", errno, strerror(errno));
    }
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed setup_server_socket() successfully");

    return 0;
}



/**
 * @brief Accepts a new client connection and spawns a dedicated thread for that client.
 *
 * @param poll_fd The file descriptor of the poll instance.
 * @param sockfd The listening socket file descriptor.
 */
int poll_newconn() {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting setup_server_socket");
    struct sockaddr_in client_address;
    socklen_t client_len = sizeof(client_address);

    int sockfd = 0;
    if((sockfd = accept(server_fd, (struct sockaddr *)&client_address, &client_len)) == -1) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Accepting new connection failed: %s", errno, strerror(errno));
        return -1;
    }

    // Create a child process
    pid_t pid = fork();
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Fork() Successful: pid %d", pid);

    if (pid < 0) {
        // Error occurred
        log_message(LOG_CRITICAL, process, __func__, __FILE__, __LINE__, "CRITICAL ERR_%d: fork() failed: %s", errno, strerror(errno));
        return -1;
    } else if (pid == 0) {
        // Child process
        ppid = getppid(); cpid = getpid();
        if(process) free(process);
        process = fstring("SRVR [C-%d]", cpid);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "New client successfully connected: parent: %d, child: %d", ppid, cpid);

        generate_rsa_key_pair_4096(&client_public.key, &client_public.len, &client_private.key, &client_private.len);
        exchange_public_keys( sockfd, client_public.key, client_public.len, client_private.key, &endpoint_public.key, &endpoint_public.len, server);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "client_public.key:\n%s\nendpoint_public.key:\n%s\n", client_public.key, endpoint_public.key);
        
        // Close the server socket
        close(server_fd);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Server socket closed in child");

        // Set up server socket for individual client conversations
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Initiating listener in child process %d", cpid);
        server_port = 0;
        server_fd = setup_server_socket(&server_port);
        // Set the client socket to non-blocking mode
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Attempting to make the socket non-blocking");
        set_non_blocking(sockfd);

        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Initiating the poll for events...");
        poll_loop((void *)&sockfd);
    } else {
        // Parent process: Close child socket descriptor
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Fork sucessful. closing the child process socket.");
        close(sockfd);
    }

    // Add the new connection to the client list
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Adding the client to the list");
    add_client(manager, sockfd, client_address);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed poll_newconn() successfully");

    return sockfd;
}





/**
 * @brief Reads and handles data from an existing client.
 *
 * @param poll_fd The file descriptor of the poll instance.
 * @param sockfd The file descriptor of the client socket.
 */
void poll_data(int poll_fd, int sockfd) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting poll_data()");
    unsigned char *buffer = 0;
    size_t bytes_read = 0;

    // Read data from the client using a custom API
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "waiting to read data from the socket...");
    read_data(sockfd, &buffer, &bytes_read, server);

    if (bytes_read <= 0) {
        // Client disconnected or encountered an error
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Client %d with socket %d disconnected", cpid, sockfd);
        REMOVE_FROM_POLL(poll_fd, sockfd);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Removed socket %d from poll list", sockfd);
        close(sockfd);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Closed socket %d", sockfd);
        Alive = 0;
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Client flag set for graceful exit");
    } else {
        // Print the received data
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "%s", buffer);

        command c;
        c.sockfd = sockfd;
        c.string = strdup((const char *)buffer);
        handle_command((void *)&c);
        // Free the memory allocated by the `read_data` function
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Freeing memory location %x", buffer);
    }
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed poll_data() successfully");
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
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting poll_events() - Caught %d socket events.", num_events);
    for (int i = 0; i < num_events; ++i) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Processing event %d...", i);
        int fd = EVENT_FD(&((EVENT_STRUCT*)events)[i]);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "socket %d caused the event...", fd);
        if (EVENT_IN(&((EVENT_STRUCT*)events)[i])) {
            log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Its an incoming event...");
            if (fd == server_fd && server) {
                log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Its a new client requesting connection...");
                poll_newconn(); // Handle new client connection
            } else {
                log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "incoming data...");
                poll_data(poll_fd, fd); // Handle data from an existing client
            }
        }
    }
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed poll_events() successfully");
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
    int sockfd = *(int *)fd;

    // Set up the poll instance
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting poll_loop() - Setting up event poll for monitoring incoming data");
    int poll_fd = SETUP_POLL(process);

    int max_events = INIT_EVENT_SIZE;
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Allocating %zu bytes of memory for capturing events", max_events * sizeof(EVENT_STRUCT));
    EVENT_STRUCT* events = malloc(max_events * sizeof(EVENT_STRUCT));
    if ( !events ) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Memory allocation failed: %s", errno, strerror(errno));
        return NULL;
    }

    // Add the listening socket to the poll
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Adding socket to event poll");
    ADD_TO_POLL(poll_fd, sockfd);

    // Initiate the client manager link list
    manager = initialize_client_manager();

    // Initiate database connection
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Attempting to open a database session pool");
    void * pl = (void *)odpic_open_session_pool(config_file_path, (dpiPool **)&pl);
    
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Attempting to acquire a single session from the session pool");
    dpiConn *cn = odpic_get_session_from_pool(pl);
    
    // Polling loop
    while (Alive) {
        // Wait for events
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Awaiting new events (incoming data or new client connection)");
        int num_events = WAIT_FOR_EVENTS(poll_fd, events, max_events, process);
        if(num_events < 0){
            log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "FATAL: WAIT_FOR_EVENTS failed... immediate program termination");
            Alive = 0;
            continue;
        }

        // Process the events
        poll_events(poll_fd, events, num_events);

        // Dynamically resize the event array if it is full
        if (num_events == max_events) {
            log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Re-sizing EVENT_STRUCT* events");
            max_events *= 2;
            events = realloc(events, max_events * sizeof(EVENT_STRUCT));
            if ( ! events ) {
                log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Memory allocation failed: %s", errno, strerror(errno));
                exit(-1);
            }
        }
    }

    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Releasing database session back to session pool");
    odpic_release_session_to_pool(cn);
    
    // log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Gracefully closing database connection");
    // odpic_close_session_pool((dpiPool *)pl);

    // Cleanup
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Cleaning up \"EVENT_STRUCT* events\" structure");
    free(events);

    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Gracefully closing poll (poll_fd)");
    close(poll_fd);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed poll_loop() successfully");
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

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting exchange_public_keys() - Exchanging public keys with the end point");
    if (server_end) { // Server-side logic
        data = malloc(my_public_key_len + sizeof(uint32_t));
        if( !data ){
            log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Memory allocation failed: %s", errno, strerror(errno));
            exit(-1);
        }
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Allocated %zu bytes for storing public key", my_public_key_len + sizeof(uint32_t));
        
        data_len = htonl(my_public_key_len);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "converted public key length to network byte order");
        
        memcpy(data, &data_len, sizeof(uint32_t));
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "copied data length to the front of the \"data\" buffer");
       
        memcpy(data + sizeof(uint32_t), my_public_key, my_public_key_len);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "copy my_public_key in to \"data\" buffer");
        
        if ( write(sockfd, data, my_public_key_len + sizeof(uint32_t)) == -1) {
            log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "ERR_%d: \"write\" on socket failed: %s", errno, strerror(errno));
            return ret;
        };
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Sent public key to the other side");
        
        free(data);
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "freed \"data\" memory");

        if ( exchange_rsa_data(sockfd, &data, &data_len, server) ){
            if ( !rsa_decrypt_with_private_key(my_private_key, data, data_len, (unsigned char **)their_public_key, their_public_key_len) ) {
                ret = 0;
                log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully exchanged RSA keys amongst peers");
            }
        }        
    } else {  // Step 3: Client-side logic
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Reading peer public key length in network byte order");
        read(sockfd, &data_len, sizeof(uint32_t));
    
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Converting data length in network byte order to regular integer");
        *their_public_key_len = ntohl(data_len);
    
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Allocating %zu bytes of memory to hold peer public key", *their_public_key_len);
        if ( !(*their_public_key = malloc(*their_public_key_len)) ){
            log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "FATAL ERR_%d: Memory allocation failed: %s", errno, strerror(errno));
            exit(-1);
        }

        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Reading the peer public key in to the allocated memory");
        read(sockfd, *their_public_key, *their_public_key_len);
        
        if( !rsa_encrypt_with_public_key(*their_public_key, (const unsigned char *)my_public_key, my_public_key_len, &data, &data_len)) {
            if( exchange_rsa_data(sockfd, &data, &data_len, server) ) {
                ret = 0;
                log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully exchanged RSA keys amongst peers");
            }
        };
    }
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Freeing up \"data\" allocated memory");
    free(data);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed exchange_public_keys() successfully");
    return ret;
}