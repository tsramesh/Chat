#include "main.h"

// Global flag to indicate the server's running state (volatile ensures visibility across threads)
volatile int Alive;

// Indicates if the program is running as a server
int server = false;

// Process ID markers
int cpid = 0; // Stores child process ID
int ppid = 0; // Stores parent process ID 

// 'Parent' or 'Child' indicator
char * process = NULL;
char * config_file_path;

/**
 * Main entry point of the server application.
 * 1. Sets up the server socket.
 * 2. Enters the server loop to handle client connections and events.
 * 3. Cleans up resources upon exit.
 */
int main(int argc, char **argv) {
    // Entry logging: Log the start of the main function execution

    // Step 1: Setup the server process identifier (ppid)
    ppid = getpid();  // Get the process ID of the current process
    process = fstring("SRVR [P-%d]", ppid);  // Format the process ID into the process name string
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Main function started with %d arguments. Process ID: %d, Process name: %s", argc, ppid, process);

    // Step 2: Define the configuration file path (if provided as argument)
    config_file_path = argc <= 1 ? "/Users/tramesh/Documents/Projects/cfg/config.txt" : argv[1];
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Configuration file path: %s", config_file_path);

    // Step 3: Setup the server socket by reading the port number from the config file
    server_port = atoi(GetConfigValue(config_file_path, "PORT"));
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Opening server at port %d", server_port);

    // Step 4: Set up the server socket and log its creation
    server_fd = setup_server_socket(&server_port);
    if (server_fd == -1) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to set up the server socket on port %d", server_port);
        return -1;
    }
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Server socket successfully created with file descriptor %d", server_fd);

    // Step 5: Generate RSA public and private keys for the server
    generate_rsa_key_pair_4096(&parent_public.key, &parent_public.len, &parent_private.key, &parent_private.len);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "RSA key pair generated: Public key length %zu, Private key length %zu", parent_public.len, parent_private.len);

    // Step 6: Initialize the volatile flag to control the server loop
    Alive = 1;  // Flag to keep the server loop running
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Server loop control flag 'Alive' set to 1");

    // Step 7: Indicate that this is the server process for external components
    server = true;
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Server flag set to true");

    // Step 8: Start the server event loop, passing the server file descriptor
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting the server event loop with server_fd: %d", server_fd);
    poll_loop((void *)&server_fd);

    // Step 9: Cleanup resources and close the server socket
    if (server_fd) {
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Closing server socket with file descriptor %d", server_fd);
        close(server_fd);
    }

    // Exit logging: Log the exit of the main function
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Main function exiting successfully");

    return 0;  // Return success
}

