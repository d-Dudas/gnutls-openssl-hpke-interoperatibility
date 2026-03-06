#include "utils.h"

int openssl_keypair_to_gnutls_datum(EVP_PKEY *pkey,
                                    gnutls_datum_t *private_key_der)
{
    if (!pkey || !private_key_der)
    {
        return -1;
    }

    int ret;
    unsigned char *der = NULL;
    int der_len = 0;

    ret = openssl_privkey_to_pkcs8_der(pkey, &der, &der_len);
    if (ret != 0)
    {
        ret = -1;
        goto cleanup;
    }

    private_key_der->data = der;
    private_key_der->size = (unsigned int)der_len;
    der = NULL;

    ret = 0;

cleanup:
    if (der)
    {
        OPENSSL_free(der);
    }

    return ret;
}

int generate_keypair(openssl_x25519_keypair_t *openssl_keypair,
                     gnutls_x25519_keypair_t *gnutls_keypair)
{
    int ret;
    gnutls_datum_t private_key_der = {
        .data = NULL,
        .size = 0,
    };

    ret = openssl_generate_x25519(openssl_keypair);
    if (ret != 0)
    {
        fprintf(stderr, "OpenSSL X25519 keygen failed for recipient\n");
        goto cleanup;
    }

    ret = openssl_keypair_to_gnutls_datum(openssl_keypair->pkey,
                                          &private_key_der);
    if (ret != 0)
    {
        fprintf(stderr,
                "Failed to convert OpenSSL sender private key to DER\n");
        goto cleanup;
    }

    ret = gnutls_import_from_openssl(&private_key_der, gnutls_keypair);
    if (ret != 0)
    {
        fprintf(stderr, "GnuTLS sender import failed\n");
        goto cleanup;
    }

cleanup:
    gnutls_free(private_key_der.data);

    return ret;
}
