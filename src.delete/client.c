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
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // Convert IPv4 and IPv6 addresses from text to binary form
    inet_pton(AF_INET, server_ip, &serv_addr.sin_addr);

    // Connect to server
    connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    exchange_public_keys(sockfd, endpoint_public.key, endpoint_public.len, endpoint_private.key, &client_public.key, &client_public.len, server);

    Alive = 1;

    pthread_t thread_id;
    pthread_create(&thread_id, NULL, poll_loop, (void *)&sockfd);

    // Main communication loop
    while (Alive) {
        printf("Enter message (or type 'QUIT' to exit): ");
        fgets((char *)send_buffer, sizeof(send_buffer), stdin);
        send_buffer[strcspn((char *)send_buffer, "\n")] = '\0'; // Remove newline

        if (strcmp((char *)send_buffer, "QUIT") == 0) {
            Alive = 0;
            break;
        }
        printf("Sending %lu bytes\n", strlen((char *)send_buffer));
        write_data( sockfd, send_buffer, strlen((char *)send_buffer), false);
    }

    // Close connection
    close(sockfd);
    free(client_name);
}

int main(){
    char *interface = 0, *host;
    get_active_network_interface(&interface, &host);
    generate_rsa_key_pair_4096(&endpoint_public.key, &endpoint_public.len, &endpoint_private.key, &endpoint_private.len);
    // printf("\nEndpoint Public Key - %zu:-\n%s\n\nEndpoint Private Key - %zu:-\n%s\n", endpoint_public.len, endpoint_public.key, endpoint_private.len, endpoint_private.key);

    if (interface) {
        printf("Active Network Interface: %s - %s\n", interface, host);
        client_function(host, PORT);
    } else {
        printf("No active network interface found.\n");
    }
    free(interface);
    free(host);
}