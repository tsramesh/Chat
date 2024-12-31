#ifndef NET_H
#define NET_H

#include "common.h"
#include <netdb.h>

void get_ip_address();
void get_active_network_interface(char **intertface, char **host);

#endif // NET_H