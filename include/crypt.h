/**
 * @file crypt.h
 * @brief Header file for cryptographic functions including SHA-256 and AES-256 encryption/decryption.
 *
 * This header provides function prototypes for SHA-256 checksum generation, AES-256 encryption, and AES-256 decryption.
 */

#ifndef CRYPT_H
#define CRYPT_H

#include "common.h"

typedef struct {
    char * key;
    size_t len;
} RSA_KEY;

// RSA Public & Private Key generation
extern RSA_KEY parent_public;    // Parent process public key
extern RSA_KEY parent_private;   // Parent process private key
extern RSA_KEY client_public;    // Child process public key
extern RSA_KEY client_private;   // Child process private key
extern RSA_KEY endpoint_public;  // End point process public key
extern RSA_KEY endpoint_private; // End point process private key

#define ENCRYPT 1
#define DECRYPT 0

/**
 * @brief Computes the SHA-256 checksum of the given data.
 *
 * This function takes in data of arbitrary length and generates a SHA-256 hash of the input.
 *
 * @param data Pointer to the input data to be hashed.
 * @param data_len The length of the input data in bytes.
 * @param key Pointer to an array where the resulting SHA-256 hash will be stored (32 bytes).
 * @return 0 on success, or a non-zero value on error.
 */
int sha256(const unsigned char *data, size_t data_len, unsigned char *key);

/**
 * @brief Encrypts plaintext using AES-256 encryption.
 *
 * This function encrypts the given plaintext using the AES-256 algorithm. The encryption process 
 * produces ciphertext of the specified length.
 *
 * @param plaintext Pointer to the input plaintext to be encrypted.
 * @param plaintext_len The length of the input plaintext in bytes.
 * @param key Pointer to the AES key (32 bytes for AES-256).
 * @param ciphertext Pointer to an array where the encrypted data will be stored.
 * @param ciphertext_len Pointer to a variable that will hold the length of the encrypted ciphertext.
 * @return 0 on success, or a non-zero value on error.
 */
int aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, unsigned char *ciphertext, size_t *ciphertext_len);

/**
 * @brief Decrypts ciphertext using AES-256 decryption.
 *
 * This function decrypts the given ciphertext using the AES-256 algorithm. The decryption process
 * produces the original plaintext.
 *
 * @param ciphertext Pointer to the input ciphertext to be decrypted.
 * @param ciphertext_len The length of the input ciphertext in bytes.
 * @param key Pointer to the AES key (32 bytes for AES-256).
 * @param plaintext Pointer to an array where the decrypted plaintext will be stored.
 * @param plaintext_len Pointer to a variable that will hold the length of the decrypted plaintext.
 * @return 0 on success, or a non-zero value on error.
 */
int aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, unsigned char *plaintext, size_t *plaintext_len);
int cipher(unsigned char * in, size_t inlen, unsigned char * key, unsigned char ** out, size_t *out_len, int crypt_flag);

int generate_rsa_key_pair_4096(char **public_key, size_t *public_key_len, char **private_key, size_t *private_key_len);

int rsa_encrypt_with_public_key(const char *public_key, const unsigned char *message, size_t message_len, unsigned char **encrypted, size_t *encrypted_len);
int rsa_decrypt_with_private_key(const char *private_key, unsigned char *encrypted_data, size_t encrypted_data_len, unsigned char **decrypted_data, size_t *decrypted_data_len);

void print_openssl_error(const char *context);

#endif // CRYPT_H
