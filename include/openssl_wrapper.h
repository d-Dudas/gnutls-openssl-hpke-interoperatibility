#ifndef OPENSSL_WRAPPER_H
#define OPENSSL_WRAPPER_H

#include <openssl/evp.h>

#define RAW_X25519_LEN 32

typedef struct
{
    EVP_PKEY* pkey;

    unsigned char private_key_raw[RAW_X25519_LEN];
    size_t private_key_raw_len;

    unsigned char public_key_raw[RAW_X25519_LEN];
    size_t public_key_raw_len;
} openssl_x25519_keypair_t;

void openssl_kp_deinit(openssl_x25519_keypair_t*);

int openssl_generate_x25519(openssl_x25519_keypair_t*);

int openssl_privkey_to_pkcs8_der(
    EVP_PKEY* public_key,
    unsigned char** der,
    int* der_len);

int openssl_hpke_encap_and_seal(
    const uint8_t mode,
    const unsigned char* recipient_public_key,
    size_t recipient_public_key_len,
    EVP_PKEY* sender_private_key,
    uint16_t kem_id,
    uint16_t kdf_id,
    uint16_t aead_id,
    const unsigned char* psk,
    size_t psk_len,
    const unsigned char* psk_id,
    const unsigned char* info,
    size_t info_len,
    const unsigned char* aad,
    size_t aad_len,
    const unsigned char* plain_text,
    size_t plain_text_len,
    unsigned char** enc,
    size_t* enc_len,
    unsigned char** cipher_text,
    size_t* cipher_text_len,
    unsigned char* exp,
    size_t exp_len);

int openssl_hpke_decap_and_open(
    const uint8_t mode,
    EVP_PKEY* receiver_private_key,
    const unsigned char* sender_public_key,
    size_t sender_public_key_len,
    uint16_t kem_id,
    uint16_t kdf_id,
    uint16_t aead_id,
    const unsigned char* psk,
    size_t psk_len,
    const unsigned char* psk_id,
    const unsigned char* info,
    size_t info_len,
    const unsigned char* aad,
    size_t aad_len,
    const unsigned char* enc,
    size_t enc_len,
    const unsigned char* cipher_text,
    size_t cipher_text_len,
    unsigned char* plain_text_out,
    size_t* plain_text_out_len);

#endif /* OPENSSL_WRAPPER_H */
