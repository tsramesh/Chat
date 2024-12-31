#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include "poll.h"
#include "msg.h"
#include "conn.h"
#include "net.h"
#include "crypt.h"

// Server configuration file path
char * config_file_path = NULL;

#define SERVER_PORT 6000

#endif // CLIENT_H
