#ifndef FILE_H
#define FILE_H

#include "common.h"
#include "msg.h"

off_t get_file_size ( const char *file_path );
void split_path ( const char *path, char **directory, char **filename );
size_t get_network_mtu ( int sockfd );
size_t get_optimal_send_size ( int sockfd );
size_t send_file ( int sockfd, char * file_name_with_path );
size_t recv_file ( int sockfd, char * file_name, size_t size );

#endif // FILE_H