#include "net.h"

void get_all_nw_interface_ip_address() {
    // Declare variables for storing interface information and the host IP address
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    // Step 1: Retrieve the list of network interfaces
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Attempting to retrieve network interfaces using getifaddrs()...");
    if (getifaddrs(&ifaddr) == -1) {
        // Log failure to retrieve network interface addresses
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "getifaddrs() failed to retrieve network interfaces.");
        perror("getifaddrs");
        exit(EXIT_FAILURE); // Exit program on failure
    }
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully retrieved network interfaces.");

    // Step 2: Iterate over each network interface and retrieve its IP address
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // Skip interfaces with no address
        if (ifa->ifa_addr == NULL) {
            continue; // Logically skip to next interface if no address is available
        }

        // Get the address family (AF_INET for IPv4, AF_INET6 for IPv6)
        int family = ifa->ifa_addr->sa_family;

        // Step 3: Process IPv4 addresses
        if (family == AF_INET) { // IPv4 address
            // Retrieve and log the IPv4 address
            log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Found IPv4 address for interface: %s", ifa->ifa_name);
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                // Log the retrieved IPv4 address
                log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Interface: %s\tAddress: %s", ifa->ifa_name, host);
                printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, host);
            } else {
                // Log failure to resolve IPv4 address
                log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to resolve IPv4 address for interface: %s", ifa->ifa_name);
            }
        }
        // Step 4: Process IPv6 addresses
        else if (family == AF_INET6) { // IPv6 address
            // Retrieve and log the IPv6 address
            log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Found IPv6 address for interface: %s", ifa->ifa_name);
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                // Log the retrieved IPv6 address
                log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Interface: %s\tAddress: %s", ifa->ifa_name, host);
                printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, host);
            } else {
                // Log failure to resolve IPv6 address
                log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to resolve IPv6 address for interface: %s", ifa->ifa_name);
            }
        }
    }

    // Step 5: Free the memory allocated by getifaddrs
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Freeing memory allocated by getifaddrs()");
    freeifaddrs(ifaddr);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed retrieving and displaying network interface IP addresses.");
}


void get_active_network_interface(char **interface, char **host) {
    // Ensure the function receives valid pointers for interface and host
    if (!interface || !host) return;

    // Declare the struct for storing network interface addresses and the variable to store the host address
    struct ifaddrs *ifaddr, *ifa;
    char ifhost[NI_MAXHOST];

    // Step 1: Retrieve the list of network interfaces
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Attempting to retrieve network interfaces using getifaddrs()...");
    if (getifaddrs(&ifaddr) == -1) {
        // Log failure to retrieve network interface addresses
        log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "getifaddrs() failed to retrieve network interfaces.");
        perror("getifaddrs");
        return; // Exit the function if retrieval fails
    }
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully retrieved network interfaces.");

    // Step 2: Iterate over the network interfaces to find an active and non-loopback interface
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // Skip interfaces with no address
        if (ifa->ifa_addr == NULL) {
            log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Skipping interface %s with no address.", ifa->ifa_name);
            continue;
        }

        // Retrieve the address family (IPv4, IPv6, etc.)
        int family = ifa->ifa_addr->sa_family;

        // Step 3: Check if the interface is up and not a loopback interface
        if ((ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Interface %s is up and not a loopback.", ifa->ifa_name);

            // Step 4: Handle both IPv4 and IPv6 addresses (currently handling IPv4)
            if (family == AF_INET) { // Currently handling only IPv4
                log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Found IPv4 address for interface: %s", ifa->ifa_name);
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), ifhost, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                    // Successfully resolved the address to a string
                    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Resolved address for %s: %s", ifa->ifa_name, ifhost);

                    // Allocate memory for the interface name and host address, then assign them to the provided pointers
                    *interface = strdup(ifa->ifa_name);
                    *host = strdup(ifhost);

                    // Log successful assignment of interface and host address
                    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Assigned interface: %s and host address: %s", *interface, *host);
                    break; // Exit the loop once an active interface is found
                } else {
                    // Log failure to resolve the address for this interface
                    log_message(LOG_ERROR, process, __func__, __FILE__, __LINE__, "Failed to resolve address for interface %s", ifa->ifa_name);
                }
            }
        } else {
            log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Interface %s is either down or a loopback address.", ifa->ifa_name);
        }
    }

    // Step 5: Free the memory allocated by getifaddrs
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Freeing memory allocated by getifaddrs()");
    freeifaddrs(ifaddr);
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Completed retrieval of active network interface.");
}
