#ifndef CONN_H
#define CONN_H

#include "common.h"
#include "msg.h"

typedef struct Client {
    int fd;                      // Socket file descriptor for the client
    char name[50];               // User-friendly name
    struct sockaddr_in address;  // Client's socket address
    bool authenticated;          // Authentication status
    struct Client *next;         // Pointer to the next client
} Client;

typedef struct ClientManager {
    Client *head;      // Head of the linked list
    size_t num_clients; // Number of connected clients
} ClientManager;

pthread_mutex_t clients_mutex; // Mutex for synchronizing access to the clients list

extern ClientManager *manager;

ClientManager* initialize_client_manager();
void cleanup_client_manager(ClientManager *manager);
bool add_client(ClientManager *manager, int fd, struct sockaddr_in address);
bool remove_client(ClientManager *manager, int fd);
bool authenticate_client(ClientManager *manager, int fd, const char *name);
Client* get_client_by_name(ClientManager *manager, const char *name);
Client* get_client_by_fd(ClientManager *manager, int fd);
void list_clients(ClientManager *manager, int fd);

#endif // CONN_H