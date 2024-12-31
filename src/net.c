#include "net.h"

void get_all_nw_interface_ip_address() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        int family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) { // IPv4 address
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, host);
            }
        } else if (family == AF_INET6) { // IPv6 address
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, host);
            }
        }
    }

    freeifaddrs(ifaddr);
}

void get_active_network_interface(char **interface, char **host) {
    struct ifaddrs *ifaddr, *ifa;
    if (!interface || !host) return;

    char ifhost[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) 
            continue;

        int family = ifa->ifa_addr->sa_family;

        // Check if the interface is up and not a loopback
        if ((ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            // Check for IPv4 or IPv6 address
            if (family == AF_INET ) { // || family == AF_INET6) {
                getnameinfo(ifa->ifa_addr, (family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)), ifhost, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                *interface = strdup(ifa->ifa_name);
                *host = strdup(ifhost);
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return; //  active_interface;
}