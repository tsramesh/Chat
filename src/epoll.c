#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __linux__
    #include <sys/epoll.h>
    #define INIT_EVENT_SIZE 10
    #define EVENT_STRUCT struct epoll_event
    #define CREATE_EPOLL() epoll_create1(0)
    #define ADD_EPOLL_FD(epoll_fd, fd) { \
        struct epoll_event ev; \
        ev.events = EPOLLIN; \
        ev.data.fd = fd; \
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev); \
    }
    #define REMOVE_EPOLL_FD(epoll_fd, fd) epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL)
    #define WAIT_EPOLL(epoll_fd, events, max_events) epoll_wait(epoll_fd, events, max_events, -1)
    #define EVENT_FD(event) ((struct epoll_event*)event)->data.fd
    #define EVENT_IN(event) ((struct epoll_event*)event)->events & EPOLLIN
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <sys/event.h>
    #include <sys/time.h>
    #define INIT_EVENT_SIZE 10
    #define EVENT_STRUCT struct kevent
    #define CREATE_EPOLL() kqueue()
    #define ADD_EPOLL_FD(epoll_fd, fd) { \
        struct kevent ke; \
        EV_SET(&ke, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL); \
        kevent(epoll_fd, &ke, 1, NULL, 0, NULL); \
    }
    #define REMOVE_EPOLL_FD(epoll_fd, fd) { \
        struct kevent ke; \
        EV_SET(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL); \
        kevent(epoll_fd, &ke, 1, NULL, 0, NULL); \
    }
    #define WAIT_EPOLL(epoll_fd, events, max_events) kevent(epoll_fd, NULL, 0, events, max_events, NULL)
    #define EVENT_FD(event) ((struct kevent*)event)->ident
    #define EVENT_IN(event) ((struct kevent*)event)->filter == EVFILT_READ
#endif

void* setup_epoll() {
    int epoll_fd = CREATE_EPOLL();
    if (epoll_fd == -1) {
        perror("create epoll failed");
        exit(EXIT_FAILURE);
    }
    return (void*)(intptr_t)epoll_fd;
}

void add_to_epoll(void* epoll_fd, int fd) {
    ADD_EPOLL_FD((intptr_t)epoll_fd, fd);
}

void remove_from_epoll(void* epoll_fd, int fd) {
    REMOVE_EPOLL_FD((intptr_t)epoll_fd, fd);
}

int wait_for_epoll(void* epoll_fd, void* events, int max_events) {
    return WAIT_EPOLL((intptr_t)epoll_fd, events, max_events);
}

void handle_events(void* epoll_fd, void* events, int num_events) {
    for (int i = 0; i < num_events; ++i) {
        int fd = EVENT_FD(&((EVENT_STRUCT*)events)[i]);
        if (EVENT_IN(&((EVENT_STRUCT*)events)[i])) {
            // Handle read event
            char buffer[1024];
            int bytes_read = read(fd, buffer, sizeof(buffer));
            if (bytes_read > 0) {
                printf("Read %d bytes from fd %d\n", bytes_read, fd);
            } else if (bytes_read == 0) {
                printf("Connection closed on fd %d\n", fd);
                remove_from_epoll(epoll_fd, fd);
                close(fd);
            } else {
                perror("read error");
            }
        }
    }
}

void* thread_function(void* arg) {
    void* epoll_fd = setup_epoll();
    int max_events = INIT_EVENT_SIZE;
    EVENT_STRUCT* events = malloc(max_events * sizeof(EVENT_STRUCT));
    if (!events) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    // Example socket to add (replace with actual socket fds)
    int socket_fd_1 = *(int*)arg;
    add_to_epoll(epoll_fd, socket_fd_1);

    while (1) {
        int num_events = wait_for_epoll(epoll_fd, events, max_events);
        if (num_events == -1) {
            perror("wait_for_epoll failed");
            free(events);
            close((intptr_t)epoll_fd);
            exit(EXIT_FAILURE);
        }

        handle_events(epoll_fd, events, num_events);

        if (num_events == max_events) {
            max_events *= 2;
            events = realloc(events, max_events * sizeof(EVENT_STRUCT));
            if (!events) {
                perror("realloc failed");
                close((intptr_t)epoll_fd);
                exit(EXIT_FAILURE);
            }
        }
    }

    free(events);
    close((intptr_t)epoll_fd);
    return NULL;
}

