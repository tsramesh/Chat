#include "client.h"

volatile int Alive = 0;
int server = false;

char *generate_client_name() {
    static int client_count = 1;
    char *name = malloc(20 * sizeof(char));
    if (!name) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    snprintf(name, 20, "Client%d", client_count++);
    return name;
}

void client_function(const char *server_ip, int server_port) {
    int sockfd;
    char *client_name = generate_client_name();
    unsigned char send_buffer[1024];

    // Set server address
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT)
    };

    // Create socket
    CHECK(sockfd = socket(AF_INET, SOCK_STREAM, 0), "Socket creation failed", (void)0, CRITICAL_ERROR, process);

    // Convert IPv4 and IPv6 addresses from text to binary form
    CHECK(inet_pton(AF_INET, server_ip, &serv_addr.sin_addr), "Converting server IPv4 / IPv6 addresses from text to binary form failed", (void)0, CRITICAL_ERROR, process);

    // Connect to server
    CHECK(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)), "Connection to server failed", (void)0, CRITICAL_ERROR, process);

    exchange_public_keys(sockfd, endpoint_public.key, endpoint_public.len, endpoint_private.key, &client_public.key, &client_public.len, server);
    printf("Public keys exchanged and connected to server as: %s\n", client_name);
    Alive = 1;

    pthread_t thread_id;
    CHECK( !pthread_create(&thread_id, NULL, poll_loop, (void *)&sockfd) ? 0 : -1, "Poll loop thread could not be spawned", (void)0, CRITICAL_ERROR, process);

    // Main communication loop
    while (Alive) {
        printf("Enter message (or type 'QUIT' to exit): ");
        fgets((char *)send_buffer, sizeof(send_buffer), stdin);
        send_buffer[strcspn((char *)send_buffer, "\n")] = '\0'; // Remove newline

        if (strcmp((char *)send_buffer, "QUIT") == 0) {
            Alive = 0;
            break;
        } else if (!strncmp((char *)send_buffer, "FILE", 4)){
            send_file(sockfd, (char *)(send_buffer+5));
        } else write_data( sockfd, send_buffer, strlen((char *)send_buffer), false);
    }

    // Close connection
    close(sockfd);
    if(client_name)free(client_name);
}

int main(int argc, char **argv){
    config_file_path = argc <= 1 ? "/Users/tramesh/Documents/Projects/cfg/config.txt" : argv[1];

    char *interface, *host;
    get_active_network_interface(&interface, &host);
    generate_rsa_key_pair_4096(&endpoint_public.key, &endpoint_public.len, &endpoint_private.key, &endpoint_private.len);
    // printf("\nEndpoint Public Key - %zu:-\n%s\n\nEndpoint Private Key - %zu:-\n%s\n", endpoint_public.len, endpoint_public.key, endpoint_private.len, endpoint_private.key);

    if (interface) {
        printf("Active Network Interface: %s - %s\n", interface, host);
        client_function(host, PORT);
    } else {
        printf("No active network interface found.\n");
    }
}