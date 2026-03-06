#ifndef UTILS_H
#define UTILS_H

#include <openssl/evp.h>
#include <gnutls/gnutls.h>

#include "openssl_wrapper.h"
#include "gnutls_wrapper.h"

int openssl_keypair_to_gnutls_datum(
    EVP_PKEY* pkey,
    gnutls_datum_t* private_key_der);

int generate_keypair(
    openssl_x25519_keypair_t* openssl_keypair,
    gnutls_x25519_keypair_t* gnutls_keypair);

#endif // UTILS_H
