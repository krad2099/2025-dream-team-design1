/**
 * @file simple_crypto.c
 * @author Dream Team
 * @brief Simplified Crypto API Implementation
 * @date 2025
 *
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/md5.h>

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(const uint8_t *plaintext, size_t len, const uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    int result;

    // Ensure valid length
    if (len == 0 || len % BLOCK_SIZE != 0)
        return -1;

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, KEY_SIZE, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error

    // Encrypt each block
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(const uint8_t *ciphertext, size_t len, const uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result;

    // Ensure valid length
    if (len == 0 || len % BLOCK_SIZE != 0)
        return -1;

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, KEY_SIZE, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the data to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(const void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    return wc_Md5Hash((const uint8_t *)data, len, hash_out);
}

#endif
