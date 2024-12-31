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

    ppid = getpid();
    process = fstring("SRVR [P-%d]", ppid);

    config_file_path = argc <= 1 ? "/Users/tramesh/Documents/Projects/cfg/config.txt" : argv[1];

    // Step 1: Setup the server socket
    printf("Opening server at port %d\n", server_port = atoi(GetConfigValue(config_file_path, "PORT")));

    // Step 2: Set up the server on the defined port
    server_fd = setup_server_socket(&server_port);

    // Generate RSA public & private keys
    generate_rsa_key_pair_4096(&parent_public.key, &parent_public.len, &parent_private.key, &parent_private.len);

    // Step 2: Initialize the volatile flag to control the server loop
    Alive = 1;

    // Step 3: Indicate that this is the server process (used by external components)
    server = true;

    // Step 4: Start the server event loop, passing the server file descriptor
    poll_loop((void *)&server_fd);

    // Step 5: Cleanup resources and close the server socket
    if(server_fd) close(server_fd);

    return 0;
}
