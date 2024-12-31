#include "zip.h"

#define CHUNK 1024  // Define a chunk size for compression

/**
 * Checks if the given data is compressed using the zlib format (as per RFC 1950).
 *
 * @param data  Pointer to the input data to be checked.
 * @param len   Length of the input data.
 *
 * @return      `true` if the data appears to be zlib-compressed; `false` otherwise.
 *
 * Explanation:
 * - The zlib header format (RFC 1950) specifies the following:
 *   1. The first byte (CMF - Compression Method and Flags) contains:
 *      - Bits 0-3: Compression Method (must be 8 for deflate).
 *      - Bits 4-7: Compression Info (not validated in this function).
 *   2. The second byte (FLG - Flags) contains various flags.
 *   3. The first two bytes (CMF and FLG) must satisfy the checksum:
 *      `(CMF << 8 | FLG) % 31 == 0`.
 *
 * - If the data is too short (less than 2 bytes), it is considered not compressed.
 */
bool is_compressed(const unsigned char *data, size_t len) {
    if (len < 2) {
        return false; // Data is too short to contain a valid zlib header
    }

    uint8_t cmf = data[0]; // First byte: Compression Method and Flags
    uint8_t flg = data[1]; // Second byte: Flags

    // Check if the compression method is 8 (deflate) and if the header checksum is valid
    if ((cmf & 0x0F) == 8 && ((cmf << 8 | flg) % 31 == 0)) {
        return true; // The data has a valid zlib header
    }

    return false; // The data does not appear to be zlib-compressed
}

/**
 * Compresses the input data using the zlib library.
 *
 * @param source        Pointer to the input data to be compressed.
 * @param source_len    Length of the input data.
 * @param dest          Pointer to the output buffer for the compressed data (allocated within the function).
 * @param dest_len      Pointer to store the length of the compressed data.
 *
 * @return              Z_OK on success, or an appropriate zlib error code:
 *                      - Z_MEM_ERROR if memory allocation fails.
 *                      - Z_BUF_ERROR if the output buffer size is insufficient.
 *                      - Other zlib error codes from deflateInit or deflate.
 *
 * Usage:
 * - The caller must free the `dest` buffer allocated by this function.
 * - Ensure the zlib library is included in your build process.
 */
int compress_data(const unsigned char *source, size_t source_len, unsigned char **dest, size_t *dest_len) {
    z_stream stream;  // zlib compression stream structure
    int ret;

    // Allocate memory for the compressed data
    *dest_len = compressBound(source_len); // Get the maximum possible size for compressed data
    *dest = malloc(*dest_len);            // Allocate memory for the output buffer
    if (*dest == NULL) {                  // Handle memory allocation failure
        return Z_MEM_ERROR;
    }

    // Initialize the compression stream structure
    stream.zalloc = Z_NULL;               // Use default memory allocation
    stream.zfree = Z_NULL;                // Use default memory free
    stream.opaque = Z_NULL;               // No custom state needed
    stream.avail_in = source_len;         // Size of input data
    stream.next_in = (Bytef *)source;     // Pointer to input data
    stream.avail_out = *dest_len;         // Size of output buffer
    stream.next_out = (Bytef *)*dest;     // Pointer to output buffer

    // Initialize the compression process with default compression level
    ret = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {                    // Handle initialization failure
        free(*dest);                      // Free allocated memory
        return ret;
    }

    // Perform the compression in one step, with the finish flag
    ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {            // Handle compression errors
        deflateEnd(&stream);              // Clean up the zlib stream
        free(*dest);                      // Free allocated memory
        return ret == Z_OK ? Z_BUF_ERROR : ret; // Return appropriate error code
    }

    // Update the output length with the actual size of compressed data
    *dest_len = stream.total_out;

    // Clean up and return success
    deflateEnd(&stream);
    return Z_OK;
}

/**
 * Decompresses the input data using the zlib library.
 *
 * @param source        Pointer to the input compressed data.
 * @param source_len    Length of the input data.
 * @param dest          Pointer to the output buffer for decompressed data (allocated within the function).
 * @param dest_len      Pointer to store the length of the decompressed data.
 *
 * @return              Z_OK on success, or an appropriate zlib error code:
 *                      - Z_MEM_ERROR if memory allocation or reallocation fails.
 *                      - Other zlib error codes from inflateInit or inflate.
 *                      - Returns 0 if the data is not compressed (as determined by `is_compressed`).
 *
 * Usage:
 * - The caller must free the `dest` buffer allocated by this function unless the data is not compressed.
 * - Ensure the `is_compressed` function is implemented to determine if the input data is compressed.
 */
int decompress_data(const unsigned char *source, size_t source_len, unsigned char **dest, size_t *dest_len) {
    z_stream stream;  // zlib decompression stream structure
    int ret;

    // Check if the input data is already uncompressed
    if (!is_compressed(source, source_len)) {
        *dest_len = source_len;         // Set output length to input length
        *dest = (uint8_t *)source;     // Point to the original input buffer
        return 0;                      // Return success without decompression
    }

    // Initial guess for the decompressed buffer size
    *dest_len = source_len * 2;
    *dest = malloc(*dest_len);         // Allocate memory for the output buffer
    if (*dest == NULL) {               // Handle memory allocation failure
        return Z_MEM_ERROR;
    }

    // Initialize the decompression stream structure
    stream.zalloc = Z_NULL;            // Use default memory allocation
    stream.zfree = Z_NULL;             // Use default memory free
    stream.opaque = Z_NULL;            // No custom state needed
    stream.avail_in = source_len;      // Size of input data
    stream.next_in = (Bytef *)source;  // Pointer to input data
    stream.avail_out = *dest_len;      // Size of output buffer
    stream.next_out = (Bytef *)*dest;  // Pointer to output buffer

    // Initialize the decompression process
    ret = inflateInit(&stream);
    if (ret != Z_OK) {                 // Handle initialization failure
        free(*dest);                   // Free allocated memory
        return ret;
    }

    // Decompress the data
    while (1) {
        ret = inflate(&stream, Z_NO_FLUSH); // Perform decompression
        if (ret == Z_STREAM_END) break;    // End of the decompressed data
        if (ret != Z_OK) {                 // Handle decompression errors
            inflateEnd(&stream);           // Clean up the zlib stream
            free(*dest);                   // Free allocated memory
            return ret;
        }

        // Handle insufficient output buffer size
        if (stream.avail_out == 0) {
            *dest_len *= 2;                // Double the buffer size
            *dest = realloc(*dest, *dest_len); // Reallocate memory
            if (*dest == NULL) {           // Handle reallocation failure
                inflateEnd(&stream);
                return Z_MEM_ERROR;
            }
            stream.avail_out = *dest_len - stream.total_out; // Update available output size
            stream.next_out = (Bytef *)*dest + stream.total_out; // Update output pointer
        }
    }

    // Update the output length with the actual size of decompressed data
    *dest_len = stream.total_out;

    // Clean up and return success
    inflateEnd(&stream);
    return Z_OK;
}