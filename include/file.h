#ifndef FILE_H
#define FILE_H

#include "common.h"

#define CHUNK_SIZE (1024L * 1024L * 1024L)  // 1 GB

off_t get_file_size(const char *file_path);
size_t send_file(int sockfd, const char *file_path, unsigned char **filecontent);
size_t recv_file(const char *file_path, const unsigned char *buffer, uint64_t size)

#endif // FILE_H