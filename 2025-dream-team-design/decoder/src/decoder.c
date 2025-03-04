/*
Author: Dream Team
Date: 2025
Program: decoder.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32
#define HMAC_SIZE 32
#define NONCE_SIZE 12

/* Structure to store subscription details */
typedef struct {
    uint32_t device_id;
    uint64_t start;
    uint64_t end;
    uint32_t channel;
    uint8_t hmac[HMAC_SIZE];
} Subscription;

/* Function to derive a key using PBKDF2 */
void derive_key(const uint8_t *master_key, size_t master_key_len, const uint8_t *salt, size_t salt_len, uint8_t *out_key) {
    PKCS5_PBKDF2_HMAC((const char *)master_key, master_key_len, salt, salt_len, 100000, EVP_sha256(), AES_KEY_SIZE, out_key);
}

/* Function to verify the HMAC of a subscription */
bool verify_hmac(const Subscription *sub, const uint8_t *key) {
    uint8_t computed_hmac[HMAC_SIZE];
    HMAC(EVP_sha256(), key, AES_KEY_SIZE, (uint8_t *)sub, sizeof(Subscription) - HMAC_SIZE, computed_hmac, NULL);
    return memcmp(computed_hmac, sub->hmac, HMAC_SIZE) == 0;
}

/* Function to parse subscription data */
bool parse_subscription(const uint8_t *data, size_t data_len, Subscription *sub) {
    if (data_len != sizeof(Subscription)) {
        return false;
    }
    memcpy(sub, data, sizeof(Subscription));
    return true;
}

/* Function to decode a subscription */
bool decode_subscription(const uint8_t *master_key, size_t master_key_len, const uint8_t *subscription_data, size_t subscription_len) {
    Subscription sub;
    if (!parse_subscription(subscription_data, subscription_len, &sub)) {
        printf("Error: Invalid subscription data\n");
        return false;
    }
    
    uint8_t derived_key[AES_KEY_SIZE];
    uint8_t salt[16];
    memcpy(salt, &sub.channel, sizeof(sub.channel)); // Use channel ID as salt
    derive_key(master_key, master_key_len, salt, sizeof(salt), derived_key);

    if (!verify_hmac(&sub, derived_key)) {
        printf("Error: HMAC verification failed\n");
        return false;
    }
    
    printf("Subscription verified for Device ID: %u, Channel: %u, Start: %lu, End: %lu\n", 
           sub.device_id, sub.channel, sub.start, sub.end);
    return true;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <master_key_file> <subscription_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    FILE *key_file = fopen(argv[1], "rb");
    if (!key_file) {
        perror("Error opening master key file");
        return EXIT_FAILURE;
    }
    
    uint8_t master_key[AES_KEY_SIZE];
    if (fread(master_key, 1, AES_KEY_SIZE, key_file) != AES_KEY_SIZE) {
        perror("Error reading master key");
        fclose(key_file);
        return EXIT_FAILURE;
    }
    fclose(key_file);
    
    FILE *sub_file = fopen(argv[2], "rb");
    if (!sub_file) {
        perror("Error opening subscription file");
        return EXIT_FAILURE;
    }
    
    Subscription sub;
    if (fread(&sub, 1, sizeof(Subscription), sub_file) != sizeof(Subscription)) {
        perror("Error reading subscription file");
        fclose(sub_file);
        return EXIT_FAILURE;
    }
    fclose(sub_file);
    
    if (!decode_subscription(master_key, AES_KEY_SIZE, (uint8_t *)&sub, sizeof(Subscription))) {
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
