#ifndef POLL_H
#define POLL_H

#include "common.h"
#include "msg.h"
#include "conn.h"
#include "net.h"
#include "db.h"
#include "cmd.h"

// Platform-specific includes and macros
#ifdef __linux__
    #include <sys/epoll.h>
    #define INIT_EVENT_SIZE 10
    #define EVENT_STRUCT struct epoll_event

    // Replaces CREATE_POLL
    #define SETUP_POLL(process) ({ \
        int epoll_fd = epoll_create1(0); \
        CHECK(epoll_fd, "epoll_create1 failed", (void)0, CRITICAL_ERROR); \
        epoll_fd; \
    })

    // Adds a file descriptor to the epoll instance
    #define ADD_TO_POLL(epoll_fd, fd, process) { \
        struct epoll_event ev = {0}; \
        ev.events = EPOLLIN; /* Monitor for input events */ \
        ev.data.fd = fd; \
        CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev), "epoll_ctl ADD failed", (void)0, CRITICAL_ERROR, process); \
    }

    // Removes a file descriptor from the epoll instance
    #define REMOVE_FROM_POLL(epoll_fd, fd, process) { \
        CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL), "epoll_ctl DEL failed", (void)0, CRITICAL_ERROR, process); \
    }

    // Waits for events to occur on the epoll instance
    #define WAIT_FOR_EVENTS(epoll_fd, events, max_events, process) ({ \
        int num_events = epoll_wait(epoll_fd, events, max_events, -1); \
        CHECK(num_events, "epoll_wait failed", (void)0, 0, process); \
        num_events; \
    })

    // Disables a monitored file descriptor in the epoll instance
    #define DISABLE_EVENT(epoll_fd, fd) do { \
        struct epoll_event ev = {0}; \
        ev.events = 0; /* Disable all events */ \
        ev.data.fd = fd; \
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) { \
            perror("Failed to disable event"); \
        } \
    } while (0)

    // Enables a file descriptor in the epoll instance
    #define ENABLE_EVENT(epoll_fd, fd) do { \
        struct epoll_event ev = {0}; \
        ev.events = EPOLLIN; /* Re-enable input events */ \
        ev.data.fd = fd; \
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) { \
            perror("Failed to enable event"); \
        } \
    } while (0)

    // Retrieves the file descriptor associated with an event
    #define EVENT_FD(event) ((struct epoll_event*)event)->data.fd

    // Checks if the event is an input event
    #define EVENT_IN(event) (((struct epoll_event*)event)->events & EPOLLIN)
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <sys/event.h>
    #include <sys/time.h>
    #define INIT_EVENT_SIZE 10
    #define EVENT_STRUCT struct kevent

    // Replaces CREATE_POLL
    #define SETUP_POLL(process) ({ \
        int kq = kqueue(); \
        CHECK(kq, "kqueue failed", (void)0, CRITICAL_ERROR, process); \
        kq; \
    })

    // Adds a file descriptor to the kqueue instance
    #define ADD_TO_POLL(epoll_fd, fd) { \
        struct kevent ke; \
        EV_SET(&ke, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL); \
        kevent(epoll_fd, &ke, 1, NULL, 0, NULL); \
    }

    // Removes a file descriptor from the kqueue instance
    #define REMOVE_FROM_POLL(epoll_fd, fd) { \
        struct kevent ke; \
        EV_SET(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL); \
        kevent(epoll_fd, &ke, 1, NULL, 0, NULL); \
    }

    // Waits for events to occur on the kqueue instance
    #define WAIT_FOR_EVENTS(epoll_fd, events, max_events, process) ({ \
        int num_events = 0; \
        num_events = kevent(epoll_fd, NULL, 0, events, max_events, NULL); \
        CHECK(num_events, "wait_for_epoll failed", (void)0, 0, process); \
        num_events; \
    })

    // Disables a monitored file descriptor in the kqueue instance
    #define DISABLE_EVENT(kq_fd, fd) do { \
        struct kevent change; \
        EV_SET(&change, fd, EVFILT_READ, EV_DISABLE, 0, 0, NULL); \
        if (kevent(kq_fd, &change, 1, NULL, 0, NULL) == -1) { \
            perror("Failed to disable event"); \
        } \
    } while (0)

    // Enables a file descriptor in the kqueue instance
    #define ENABLE_EVENT(kq_fd, fd) do { \
        struct kevent change; \
        EV_SET(&change, fd, EVFILT_READ, EV_ENABLE, 0, 0, NULL); \
        if (kevent(kq_fd, &change, 1, NULL, 0, NULL) == -1) { \
            perror("Failed to enable event"); \
        } \
    } while (0)

    // Retrieves the file descriptor associated with an event
    #define EVENT_FD(event) ((struct kevent*)event)->ident

    // Checks if the event is an input event
    #define EVENT_IN(event) ((struct kevent*)event)->filter == EVFILT_READ
#endif

/**
 * @brief The initial size of the event structure.
 * 
 * This macro defines the size of the event structure used for monitoring I/O events. 
 * This size may need to be adjusted based on the system or specific use case.
 */
#define INIT_EVENT_SIZE 10

/**
 * @brief Set up the server socket.
 *
 * This function creates a new listener socket allowing other client connections.
 * @return 0 if unsuccessful, or a non-zero value if a server socket is set up.
 */
int setup_server_socket(int *port);

/**
 * @brief Set a socket to non-blocking mode.
 *
 * This function sets a given socket to non-blocking mode, allowing asynchronous I/O operations.
 * 
 * @param socket_fd The file descriptor of the socket to set to non-blocking mode.
 * @return 0 if successful, or a non-zero value if an error occurred.
 */
int set_non_blocking(int socket_fd);

/**
 * @brief Handle new connection event for a polling file descriptor.
 *
 * This function is called when a new connection event is detected on the given socket.
 * It handles the necessary setup or processing for the new connection.
 * 
 * @param poll_fd The file descriptor for the poll instance.
 * @param sockfd The file descriptor for the socket associated with the new connection.
 */
// void poll_newconn(int poll_fd, int sockfd);
int poll_newconn();

/**
 * @brief Handle data event for a polling file descriptor.
 *
 * This function is called when a data event is detected on the given socket.
 * It processes the incoming data for that socket.
 * 
 * @param poll_fd The file descriptor for the poll instance.
 * @param sockfd The file descriptor for the socket receiving data.
 */
void poll_data(int poll_fd, int sockfd);

/**
 * @brief Process events for a polling file descriptor.
 *
 * This function processes the events that are detected on the poll instance, 
 * handling the specified number of events for the given socket.
 * 
 * @param poll_fd The file descriptor for the poll instance.
 * @param events The events detected on the poll instance.
 * @param num_events The number of events detected.
 * @param sockfd The file descriptor for the socket associated with the events.
 */
// void poll_events(int poll_fd, void* events, int num_events, int sockfd);
void poll_events(int poll_fd, void* events, int num_events);

/**
 * @brief Polling loop for handling multiple file descriptors.
 *
 * This function continuously checks for events on the given file descriptor, 
 * calling the appropriate handlers as events are detected.
 * 
 * @param fd A pointer to the file descriptor to be monitored.
 * @return A void pointer, typically used for thread management.
 */
void* poll_loop(void * fd);

int exchange_public_keys(int sockfd, const char *my_public_key, size_t my_public_key_len, const char *my_private_key, 
                         char **their_public_key, size_t *their_public_key_len, bool server_end);

size_t rsa_socket_data(int sockfd, unsigned char **encrypted_data, size_t *encrypted_data_len, bool server_end);
size_t rsa_socket_data_s(int sockfd, unsigned char **encrypted_data, size_t *encrypted_data_len, bool server_end);

#endif // POLL_H
