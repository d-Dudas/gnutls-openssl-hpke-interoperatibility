#ifndef OPENSSL_WRAPPER_H
#define OPENSSL_WRAPPER_H

#include <openssl/evp.h>

#define RAW_X25519_LEN 32

typedef struct
{
    EVP_PKEY* public_key;

    unsigned char private_key_raw[RAW_X25519_LEN];
    size_t private_key_raw_len;

    unsigned char public_key_raw[RAW_X25519_LEN];
    size_t public_key_raw_len;
} openssl_x25519_keypair_t;

typedef struct
{
    unsigned char* enc;
    size_t enclen;

    unsigned char* ct;
    size_t ctlen;

    unsigned char exp[32];
    size_t explen;
} openssl_hpke_sender_out_t;

void openssl_kp_deinit(openssl_x25519_keypair_t*);
void openssl_hpke_sender_out_deinit(openssl_hpke_sender_out_t*);

int openssl_generate_x25519(openssl_x25519_keypair_t*);

int openssl_privkey_to_pkcs8_der(
    EVP_PKEY* public_key,
    unsigned char** der,
    int* der_len);

int openssl_hpke_encap_and_seal(
    const unsigned char* recip_pub,
    size_t recip_publen,
    uint16_t kem_id,
    uint16_t kdf_id,
    uint16_t aead_id,
    const unsigned char* info,
    size_t infolen,
    const unsigned char* aad,
    size_t aadlen,
    const unsigned char* pt,
    size_t ptlen,
    openssl_hpke_sender_out_t* out);

#endif /* OPENSSL_WRAPPER_H */
