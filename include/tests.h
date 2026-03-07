#ifndef TESTS_H
#define TESTS_H

#include <gnutls/abstract.h>

int test_openssl_sender_gnutls_recipient_base(
    const unsigned char* recipient_public_key_raw,
    const size_t recipient_public_key_raw_len,
    const gnutls_privkey_t recipient_private_key);

int test_openssl_sender_gnutls_recipient_psk(
    const unsigned char* recipient_public_key_raw,
    const size_t recipient_public_key_raw_len,
    const gnutls_privkey_t recipient_private_key);

#endif // TESTS_H
