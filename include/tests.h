#ifndef TESTS_H
#define TESTS_H

#include "openssl_wrapper.h"
#include "gnutls_wrapper.h"

int test_openssl_sender_gnutls_recipient_base(
    const openssl_x25519_keypair_t* ossl_keypair,
    const gnutls_x25519_keypair_t* gnutls_keypair);

int test_openssl_sender_gnutls_recipient_psk(
    const openssl_x25519_keypair_t* ossl_keypair,
    const gnutls_x25519_keypair_t* gnutls_keypair);

#endif // TESTS_H
