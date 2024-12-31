/**
 * @file crypt.c
 * @brief Implementation of cryptographic functions including SHA-256 and AES-256 encryption/decryption.
 *
 * This file implements functions for SHA-256 checksum calculation and AES-256 encryption and decryption.
 * These functions utilize OpenSSL's EVP (envelope) library for cryptographic operations.
 */

#include "crypt.h"

// RSA Public & Private Key generation
RSA_KEY parent_public;    // Parent process public key
RSA_KEY parent_private;   // Parent process private key
RSA_KEY client_public;    // Child process public key
RSA_KEY client_private;   // Child process private key
RSA_KEY endpoint_public;  // End point process public key
RSA_KEY endpoint_private; // End point process private key

/**
 * @brief Computes the SHA-256 checksum of the given data.
 *
 * This function calculates the SHA-256 hash of the provided data and stores the result in the `key` array.
 * It uses the OpenSSL EVP library to handle the SHA-256 hash computation.
 *
 * @param data Pointer to the input data to be hashed.
 * @param data_len The length of the input data in bytes.
 * @param key Pointer to an array where the resulting SHA-256 hash will be stored (32 bytes).
 * @return 0 on success, or a non-zero value on error.
 */
int sha256(const unsigned char *data, size_t data_len, unsigned char *key) {
    EVP_MD_CTX *ctx = 0; unsigned int hash_len;
    if( (ctx = EVP_MD_CTX_new()) ) {
        if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) // Initialize the digest context for SHA-256
        if(EVP_DigestUpdate(ctx, data, data_len)) // Update the digest with the input data
        if(EVP_DigestFinal_ex(ctx, key, &hash_len)) // Finalize the digest and store the result in `key`
        EVP_MD_CTX_free(ctx); // Free the context
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");

        return 0;
    }
    return -1;
}

/**
 * @brief Encrypts plaintext using AES-256 encryption.
 *
 * This function encrypts the provided plaintext using the AES-256 algorithm in CBC mode. The encryption 
 * process produces ciphertext, and the ciphertext length is returned in `ciphertext_len`.
 *
 * @param in Pointer to the input to be encrypted.
 * @param inlen The length of the input in bytes.
 * @param out Pointer to the input to be encrypted.
 * @param outlen The length of the input in bytes.
 * @param crypt_flag Flag to indicate if the call is to encrypt (value = 1) or decrypt (value = 0).
 * @return 0 on success, or -1 value on error.
 */
int aes_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                 const unsigned char *key, unsigned char *ciphertext, size_t *ciphertext_len) {
    if(sha256(plaintext, plaintext_len, key)) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL, "Failed to create encryption context", (void)0, CRITICAL_ERROR, process);

    // Initialize the encryption context with AES-256 CBC mode, using the first 16 bytes of `key` as the IV
    CHECK(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, key + 16), "AES encryption init failed", EVP_CIPHER_CTX_free(ctx), ACCEPTABLE_ERROR, process);

    int len = 0;
    // Encrypt the plaintext
    CHECK(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len), "AES encryption failed", EVP_CIPHER_CTX_free(ctx), ACCEPTABLE_ERROR, process);
    *ciphertext_len = len;

    // Finalize the encryption and append any remaining ciphertext
    CHECK(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len), "AES encryption finalization failed", EVP_CIPHER_CTX_free(ctx), ACCEPTABLE_ERROR, process);
    *ciphertext_len += len;

    // Free the context
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
/*int cipher(unsigned char *in, size_t inlen, unsigned char *key, unsigned char **out, size_t *outlen, int crypt_flag) {
    size_t len;

    if(crypt_flag){ // If encrypting then the key is empty; if decrypting then use the content of key as passed
        if(sha256(in, inlen, key))
            return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_cfb(), NULL, NULL, NULL, crypt_flag) && EVP_CIPHER_CTX_set_padding(ctx, 1)) {
            len = inlen + EVP_MAX_BLOCK_LENGTH; //EVP_CIPHER_CTX_block_size(ctx);
            *out = malloc(len);
            if (EVP_CipherInit_ex(ctx, NULL, NULL, key, key+16, crypt_flag) &&
            EVP_CipherUpdate(ctx, *out, (int *)&len, in, inlen) &&
            EVP_CipherFinal_ex(ctx, *out + len, (int *)outlen)) {
            EVP_CIPHER_CTX_free(ctx);
            *outlen += len;
            printf("CIPHER: %zu, %zu\n", len, *outlen);
            return 0;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int cipher(unsigned char *in, size_t inlen, unsigned char *key, unsigned char **out, size_t *outlen, int crypt_flag) {
    size_t len = 0; EVP_CIPHER_CTX *ctx = 0;
    *out = malloc(inlen + EVP_MAX_BLOCK_LENGTH);
    // If encrypting then the key is empty; if decrypting then use the content of key as passed
    if(crypt_flag) if(sha256(in, inlen, key)) return -1;
    if( (ctx = EVP_CIPHER_CTX_new()) ) {
printf("Step-10 - %zu\n", (inlen + EVP_MAX_BLOCK_LENGTH));
        if( EVP_CipherInit_ex2(ctx, EVP_aes_256_cbc(), NULL, NULL, crypt_flag, NULL) ) {
printf("Step-11\n");
            if( EVP_CIPHER_CTX_set_padding(ctx, 1) ) {
printf("Step-12\n");
                OPENSSL_assert(EVP_CIPHER_CTX_get_key_length(ctx) == SHA256_DIGEST_LENGTH);
                OPENSSL_assert(EVP_CIPHER_CTX_get_iv_length(ctx) == SHA256_DIGEST_LENGTH/2);
                if( EVP_CipherInit_ex2(ctx, NULL, key, key+(SHA256_DIGEST_LENGTH/2), crypt_flag, NULL) ) {
printf("Step-13\n");
                    if( EVP_CipherUpdate(ctx, *out, (int *)&len, in, inlen) ) {
printf("Step-14 - %zu, %zu\n", len, inlen);
                        if( EVP_CipherFinal_ex(ctx, *out + len, (int *)outlen) ) {
                            EVP_CIPHER_CTX_free(ctx);
                            *outlen += len;
printf("Step-15 - %zu\n", *outlen);
                            return 0;
                        }
                    }
                }
            }
        }
    }
    return -1;
}

int cipher( unsigned char *input, size_t input_len,
               unsigned char *key, unsigned char **output,
               size_t *output_len, int crypt_flag) {

    char err_msg[256]; unsigned long err = 0;
    if(crypt_flag) if(sha256(input, input_len, key)) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    
    if(!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, crypt_flag)) printf("EVP_CipherInit_ex call failed\n"); // Initialize the cipher context with AES-256 CBC mode
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, key, key + 16, crypt_flag)) printf("EVP_CipherInit_ex 2nd call failed\n");           // Set the key and IV
    if(!EVP_CIPHER_CTX_set_padding(ctx, 1)) printf("EVP_CIPHER_CTX_set_padding failed\n");                                      // Enable padding
    size_t buffer_size = input_len + EVP_CIPHER_CTX_block_size(ctx);         // Allocate memory for output buffer
    *output = (unsigned char *)malloc(buffer_size);
    int len = 0, total_len = 0;
    if(!!EVP_CipherUpdate(ctx, *output, &len, input, input_len)) printf("EVP_CipherUpdate failed\n");                  // Encrypt/Decrypt the input

        err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        printf("OpenSSL Error in EVP_CipherUpdate: %s\n", err_msg);
        ERR_print_errors_fp(stderr);

    total_len += len;
    if(!EVP_CipherFinal_ex(ctx, *output + total_len, &len)) printf("EVP_CipherFinal_ex failed\n");                      // Finalize encryption/decryption and append remaining data
        err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        printf("OpenSSL Error in EVP_CipherFinal_ex: %s\n", err_msg);
        ERR_print_errors_fp(stderr);
    total_len += len;
    *output_len = total_len;
    EVP_CIPHER_CTX_free(ctx);                                                // Free the context
    return 0;
}*/

/**
 * @brief Decrypts ciphertext using AES-256 decryption.
 *
 * This function decrypts the provided ciphertext using the AES-256 algorithm in CBC mode to recover the
 * original plaintext. The plaintext is stored in the `plaintext` array, and the length of the plaintext 
 * is returned in `plaintext_len`.
 *
 * @param ciphertext Pointer to the input ciphertext to be decrypted.
 * @param ciphertext_len The length of the input ciphertext in bytes.
 * @param key Pointer to the AES key (32 bytes for AES-256).
 * @param plaintext Pointer to an array where the decrypted plaintext will be stored.
 * @param plaintext_len Pointer to a variable that will hold the length of the decrypted plaintext.
 * @return 0 on success, or a non-zero value on error.
 */
int aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                 const unsigned char *key, unsigned char *plaintext, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL, "Failed to create decryption context", (void)0, CRITICAL_ERROR, process);

    // Initialize the decryption context with AES-256 CBC mode, using the first 16 bytes of `key` as the IV
    CHECK(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, key + 16), "AES decryption init failed", EVP_CIPHER_CTX_free(ctx), ACCEPTABLE_ERROR, process);

    int len = 0;
    // Decrypt the ciphertext
    CHECK(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len), "AES decryption failed", EVP_CIPHER_CTX_free(ctx), ACCEPTABLE_ERROR, process);
    *plaintext_len = len;

    // Finalize the decryption and append any remaining plaintext
    CHECK(EVP_DecryptFinal_ex(ctx, plaintext + len, &len), "AES decryption finalization failed", EVP_CIPHER_CTX_free(ctx), ACCEPTABLE_ERROR, process);
    *plaintext_len += len;

    // Free the context
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}


/**
 * Generates a 4096-bit RSA public and private key pair.
 *
 * The generated keys are stored in memory buffers, which are allocated dynamically. 
 * The caller is responsible for freeing these buffers after use.
 *
 * @param[out] public_key Pointer to store the dynamically allocated public key string.
 * @param[out] private_key Pointer to store the dynamically allocated private key string.
 * @return int Returns 0 on success, -1 on failure.
 * 
 * Note:
 * - On failure, `public_key` and `private_key` are freed if they were allocated.
 * - Uses OpenSSL's EVP_PKEY API for key generation.
 */
int generate_rsa_key_pair_4096(char **public_key, size_t *public_key_len, char **private_key, size_t *private_key_len) {
    int ret = 0;  // Return value to indicate success or failure.

    // Create a context for key generation using RSA.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;  // Placeholder for the generated key pair.

    // Create memory BIOs to store the PEM-encoded keys in memory.
    BIO *pub_bio = BIO_new(BIO_s_mem()), *priv_bio = BIO_new(BIO_s_mem());

    // Check for initialization errors and start key generation.
    if (!ctx || !pub_bio || !priv_bio || 
        EVP_PKEY_keygen_init(ctx) <= 0 ||  // Initialize the key generation context.
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0 ||  // Set key size to 4096 bits.
        EVP_PKEY_keygen(ctx, &pkey) <= 0 ||  // Generate the key pair.
        !PEM_write_bio_PUBKEY(pub_bio, pkey) ||  // Write the public key to the memory BIO.
        !PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL)) {  // Write the private key to the memory BIO.
        
        // If any error occurs, print the error message and set the return value to -1.
        printf("Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;

    } else {
        // Determine the lengths of the keys in memory.
        size_t pub_len = BIO_pending(pub_bio), priv_len = BIO_pending(priv_bio);

        // Allocate memory for the public and private keys.
        if (!(*public_key = malloc(pub_len + 1)) || !(*private_key = malloc(priv_len + 1))) {
            ret = -1;  // Memory allocation failed.
        } else {
            // Read the keys from the BIOs into the allocated buffers.
            BIO_read(pub_bio, *public_key, pub_len);
            BIO_read(priv_bio, *private_key, priv_len);

            // Null-terminate the key strings.
            (*public_key)[pub_len] = '\0';
            *public_key_len = pub_len;
            (*private_key)[priv_len] = '\0';
            *private_key_len = priv_len;
        }
    }

    // Free resources to avoid memory leaks.
    BIO_free(pub_bio);  // Free the memory BIO for the public key.
    BIO_free(priv_bio);  // Free the memory BIO for the private key.
    EVP_PKEY_free(pkey);  // Free the generated key pair.
    EVP_PKEY_CTX_free(ctx);  // Free the key generation context.

    // Free allocated buffers if an error occurred.
    if (ret == -1) {
        if (*public_key) free(*public_key);
        if (*private_key) free(*private_key);
    }

    return ret;  // Return 0 on success, -1 on failure.
}

/**
 * Encrypts a plaintext message using an RSA public key.
 *
 * @param public_key   A string containing the PEM-encoded RSA public key.
 *                     Example: A PEM string starting with "-----BEGIN PUBLIC KEY-----".
 * @param message      A pointer to the plaintext message to be encrypted.
 * @param message_len  The length of the plaintext message in bytes.
 * @param encrypted    A pointer to a buffer where the encrypted message will be stored.
 *                     The buffer is dynamically allocated within the function and must be freed by the caller.
 * @param encrypted_len A pointer to a size_t where the size of the encrypted message will be stored.
 *
 * @return 0 on success, indicating encryption was successful and the encrypted message is available.
 *         -1 on failure, in which case the encrypted buffer is not valid.
 */
int rsa_encrypt_with_public_key(const char *public_key, const unsigned char *message, size_t message_len, unsigned char **encrypted, size_t *encrypted_len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIO *pub_bio = NULL;
    size_t outlen = 0, offset = 0;
    int ret = -1;

    *encrypted_len = 0;

    // Create a memory BIO for the private key
    if ((pub_bio = BIO_new_mem_buf(public_key, -1)))
    // Read the private key from the BIO
    if ((pkey = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL)))
    // Create a decryption context for the private key
    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) && (EVP_PKEY_encrypt_init(ctx) > 0)) {
        ret = 0;
        // Determine the maximum permissible size for a single encrypted chunk
        size_t key_size = EVP_PKEY_size(pkey) - 11; // Subtract overhead for padding

        while(message_len > *encrypted_len){
            size_t chunk_size = ((message_len - offset) > key_size) ? key_size : (message_len - offset);

            if (EVP_PKEY_encrypt(ctx, NULL, &outlen, message + *encrypted_len, chunk_size) > 0) {
                // Allocate & adjust the buffer size to hold the final encrypted data
                *encrypted = realloc( *encrypted, outlen + *encrypted_len );
                // Encrypt in chunks
                if (EVP_PKEY_encrypt(ctx, *encrypted + *encrypted_len, &outlen, message + offset, chunk_size) > 0) {
                    // Increase the offset from where the next encrypt data is to be stored
                    *encrypted_len += outlen;
                    offset += chunk_size;
                }
            } else {
                ret = -1;
                break;
            }
        }
    }

    BIO_free(pub_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int rsa_decrypt_with_private_key(const char *private_key, unsigned char *encrypted_data, size_t encrypted_data_len, unsigned char **decrypted_data, size_t *decrypted_data_len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIO *priv_bio = NULL;
    size_t outlen = 0, offset = 0;
    int ret = -1;

    // Create a memory BIO for the private key
    if ((priv_bio = BIO_new_mem_buf(private_key, -1)))
    // Read the private key from the BIO
    if ((pkey = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL)))
    // Create a decryption context for the private key
    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)))
    if (EVP_PKEY_decrypt_init(ctx) > 0) {
        ret = 0; // Success

        // Determine the maximum permissible size for a single encrypted chunk
        size_t key_size = EVP_PKEY_size(pkey);

        // Allocate buffer to hold the final decrypted data
       if((*decrypted_data = malloc(encrypted_data_len))) // Worst-case size (decrypted data <= encrypted data)
            memset(*decrypted_data, 0, encrypted_data_len);

        // Decrypt in chunks
        while (offset < encrypted_data_len) {
            size_t chunk_size = (encrypted_data_len - offset > key_size) ? key_size : encrypted_data_len - offset;

            printf("Decrypt Chunk size: %zu\n", chunk_size);

            // Determine the required buffer size for the decrypted output
            if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_data + offset, chunk_size) > 0) {
                // Decrypt the current chunk
                if (EVP_PKEY_decrypt(ctx, *decrypted_data + *decrypted_data_len, &outlen, encrypted_data + offset, chunk_size) > 0) {
                    // Increase the offset from where the next decrypt data is to be stored
                    *decrypted_data_len += outlen;
                    offset += chunk_size;
                }
            } else {
                ret = -1;
                break;
            }
        }
    }

    BIO_free(priv_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return ret; // Return status
}