#include "conn.h"

ClientManager* initialize_client_manager() {
    ClientManager *manager = (ClientManager *)malloc(sizeof(ClientManager));
    if (!manager) {
        fprintf(stderr, "Failed to initialize ClientManager\n");
        return NULL;
    }

    manager->head = NULL;
    manager->num_clients = 0;
    return manager;
}

void cleanup_client_manager(ClientManager *manager) {
    Client *current = manager->head;
    while (current) {
        Client *next = current->next;
        free(current);
        current = next;
    }

    free(manager);
}

bool add_client(ClientManager *manager, int fd, struct sockaddr_in address) {
    // Allocate memory for the new client
    Client *new_client = (Client *)malloc(sizeof(Client));
    if (!new_client) {
        fprintf(stderr, "Memory allocation failed for new client\n");
        return false;
    }

    // Initialize client properties
    new_client->fd = fd;
    new_client->address = address;
    new_client->authenticated = false;
    new_client->name[0] = '\0'; // Unset name
    new_client->next = NULL;

    // Add client to the head of the list
    new_client->next = manager->head;
    manager->head = new_client;

    // Increment client count
    manager->num_clients++;
    return true;
}

bool remove_client(ClientManager *manager, int fd) {
    Client *current = manager->head;
    Client *prev = NULL;

    while (current) {
        if (current->fd == fd) {
            // Remove the client from the list
            if (prev) {
                prev->next = current->next;
            } else {
                manager->head = current->next;
            }

            // Free client memory
            free(current);
            manager->num_clients--;

            printf("Successfully removed client %d\n", fd);
            return true;
        }
        prev = current;
        current = current->next;
    }

    fprintf(stderr, "Failed to remove client %d: Not found\n", fd);
    return false;
}

bool authenticate_client(ClientManager *manager, int fd, const char *name) {
    Client *client = get_client_by_fd(manager, fd);
    if (!client) return false;

    strncpy(client->name, name, sizeof(client->name) - 1);
    client->name[sizeof(client->name) - 1] = '\0';
    client->authenticated = true;
    return true;
}

Client* get_client_by_name(ClientManager *manager, const char *name) {
    Client *current = manager->head;

    while (current) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

Client* get_client_by_fd(ClientManager *manager, int fd) {
    pthread_mutex_lock(&clients_mutex); // Protect the linked list with a mutex for thread safety

    Client *current = manager->head;
    while (current) {
        if (current->fd == fd) {
            pthread_mutex_unlock(&clients_mutex);
            return current;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&clients_mutex);
    return NULL;
}

void list_clients(ClientManager *manager, int fd) {
    unsigned char buffer[1024];
    size_t offset = 0;

    offset += snprintf((char *)buffer + offset, sizeof(buffer) - offset, "Connected clients:\n");

    Client *current = manager->head;
    while (current) {
        if (current->authenticated) {
            offset += snprintf((char *)buffer + offset, sizeof(buffer) - offset, "- %s\n", current->name);
        }
        current = current->next;
    }

    write_data(fd, buffer, offset, false);
}
