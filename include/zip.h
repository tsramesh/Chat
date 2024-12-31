#ifndef ZIP_H
#define ZIP_H

#include "common.h"

/**
 * @file zip.h
 * @brief Header file for data compression and decompression utilities.
 *
 * This header file defines the function prototypes for checking if data is compressed,
 * and for compressing and decompressing data. It provides an abstraction layer for handling
 * compression operations.
 */

/**
 * @brief Check if the given data is compressed.
 * 
 * This function checks if the data is in a compressed format by inspecting its properties.
 * The actual implementation may involve checking headers or other characteristics typical
 * of compressed data formats.
 * 
 * @param data Pointer to the data to be checked.
 * @param len The length of the data to be checked.
 * @return `true` if the data is compressed, `false` otherwise.
 */
bool is_compressed(const unsigned char *data, size_t len);

/**
 * @brief Compress the given data.
 * 
 * This function compresses the source data and stores the compressed version in the destination
 * buffer. The function uses a compression algorithm to reduce the size of the data.
 * The compressed data is written to the `dest` pointer, and the length of the compressed data
 * is written to `dest_len`.
 *
 * @param source Pointer to the data to be compressed.
 * @param source_len The length of the data to be compressed.
 * @param dest Pointer to store the compressed data.
 * @param dest_len The length of the compressed data (output).
 * @return 0 if the compression is successful, or a non-zero value if an error occurred.
 */
int compress_data(const unsigned char *source, size_t source_len, unsigned char **dest, size_t *dest_len);

/**
 * @brief Decompress the given data.
 * 
 * This function decompresses the source data and stores the decompressed version in the destination
 * buffer. The decompressed data is written to the `dest` pointer, and the length of the decompressed data
 * is written to `dest_len`.
 *
 * @param source Pointer to the compressed data to be decompressed.
 * @param source_len The length of the compressed data.
 * @param dest Pointer to store the decompressed data.
 * @param dest_len The length of the decompressed data (output).
 * @return 0 if the decompression is successful, or a non-zero value if an error occurred.
 */
int decompress_data(const unsigned char *source, size_t source_len, unsigned char **dest, size_t *dest_len);

#endif // ZIP_H
