#include "conn.h"

ClientManager* initialize_client_manager() {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting initialize_client_manager() - Initializing client manager");

    ClientManager *manager = (ClientManager *)malloc(sizeof(ClientManager));
    if (!manager) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Memory allocation for ClientManager failed: %s", errno, strerror(errno));
        return NULL;
    }

    manager->head = NULL;
    manager->num_clients = 0;
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed initialize_client_manager() successfully");

    return manager;
}

void cleanup_client_manager(ClientManager *manager) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting cleanup_client_manager()");

    Client *current = manager->head;
    while (current) {
        Client *next = current->next;
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Freeing client with fd: %d", current->fd);
        free(current);
        current = next;
    }

    free(manager);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed cleanup_client_manager() successfully");
}

bool add_client(ClientManager *manager, int fd, struct sockaddr_in address) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting add_client() - Adding client with fd: %d", fd);

    Client *new_client = (Client *)malloc(sizeof(Client));
    if (!new_client) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Memory allocation for new client failed: %s", errno, strerror(errno));
        return false;
    }

    new_client->fd = fd;
    new_client->address = address;
    new_client->authenticated = false;
    new_client->name[0] = '\0';
    new_client->next = manager->head;
    manager->head = new_client;
    manager->num_clients++;

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed add_client() successfully. Total clients: %d", manager->num_clients);
    return true;
}

bool remove_client(ClientManager *manager, int fd) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting remove_client() - Removing client with fd: %d", fd);

    Client *current = manager->head;
    Client *prev = NULL;

    while (current) {
        if (current->fd == fd) {
            if (prev) {
                prev->next = current->next;
            } else {
                manager->head = current->next;
            }

            free(current);
            manager->num_clients--;

            log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed remove_client() successfully. Client removed - Total clients: %d", manager->num_clients);
            return true;
        }
        prev = current;
        current = current->next;
    }

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Client with fd: %d not found", fd);
    return false;
}

bool authenticate_client(ClientManager *manager, int fd, const char *name) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting authenticate_client() - Authenticating client with fd: %d", fd);

    Client *client = get_client_by_fd(manager, fd);
    if (!client) {
        log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "Client with fd: %d not found for authentication", fd);
        return false;
    }

    strncpy(client->name, name, sizeof(client->name) - 1);
    client->name[sizeof(client->name) - 1] = '\0';
    client->authenticated = true;

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed authenticate_client(). Client with fd: %d authenticated successfully with name: %s", fd, client->name);
    return true;
}

Client* get_client_by_name(ClientManager *manager, const char *name) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting get_client_by_name(). Searching for client by name: %s", name);

    Client *current = manager->head;

    while (current) {
        if (strcmp(current->name, name) == 0) {
            log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Client with name: %s found", name);
            return current;
        }
        current = current->next;
    }

    log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "Client with name: %s not found", name);
    return NULL;
}

Client* get_client_by_fd(ClientManager *manager, int fd) {
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Starting get_client_by_fd(). Searching for client by fd: %d", fd);

    pthread_mutex_lock(&clients_mutex);

    Client *current = manager->head;
    while (current) {
        if (current->fd == fd) {
            pthread_mutex_unlock(&clients_mutex);
            log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Client with fd: %d found", fd);
            return current;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&clients_mutex);
    log_message(LOG_WARN, process, __func__, __FILE__, __LINE__, "Client with fd: %d not found", fd);
    return NULL;
}

void list_clients(ClientManager *manager, int fd) {
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Starting list_clients(). Listing all connected clients for fd: %d", fd);

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
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Client list sent to fd: %d", fd);
}
