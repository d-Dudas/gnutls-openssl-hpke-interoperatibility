#ifndef GNUTLS_WRAPPER_H
#define GNUTLS_WRAPPER_H

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

typedef struct
{
    gnutls_privkey_t private_key;
    gnutls_pubkey_t public_key;
} gnutls_x25519_keypair_t;

struct openssl_hpke_sender_out_t;

void gnutls_kp_deinit(gnutls_x25519_keypair_t*);

int gnutls_import_from_openssl(
    const gnutls_datum_t* der,
    gnutls_x25519_keypair_t* out);

int gnutls_hpke_decap_and_open_base(
    const gnutls_privkey_t receiver_private_key,
    gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf,
    gnutls_hpke_aead_t aead,
    const gnutls_datum_t* info,
    const unsigned char* aad,
    size_t aadlen,
    const gnutls_datum_t* enc,
    const gnutls_datum_t* ct,
    unsigned char* pt_out,
    size_t* pt_out_len);

int gnutls_hpke_decap_and_open_psk(
    const gnutls_privkey_t receiver_private_key,
    gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf,
    gnutls_hpke_aead_t aead,
    const gnutls_datum_t* psk,
    const gnutls_datum_t* psk_id,
    const gnutls_datum_t* info,
    const unsigned char* aad,
    size_t aadlen,
    const gnutls_datum_t* enc,
    const gnutls_datum_t* ct,
    unsigned char* pt_out,
    size_t* pt_out_len);

#endif /* GNUTLS_WRAPPER_H */
