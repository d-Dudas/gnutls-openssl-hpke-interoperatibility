#include <string.h>

#include <openssl/hpke.h>

#include "gnutls_wrapper.h"
#include "openssl_wrapper.h"

static int openssl_privkey_to_gnutls_datum(EVP_PKEY *pkey,
                                           gnutls_datum_t *datum)
{
    if (!pkey || !datum)
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

    datum->data = der;
    datum->size = (unsigned int)der_len;
    der = NULL;

    ret = 0;

cleanup:
    if (der)
    {
        OPENSSL_free(der);
    }

    return ret;
}

int main(void)
{
    int ret = 1;
    openssl_x25519_keypair_t recip_ossl;
    gnutls_x25519_keypair_t recip_gnutls;
    openssl_hpke_sender_out_t sender_out;
    gnutls_datum_t recipe_der_key = {
        .data = NULL,
        .size = 0,
    };

    memset(&recip_ossl, 0, sizeof(recip_ossl));
    memset(&recip_gnutls, 0, sizeof(recip_gnutls));
    memset(&sender_out, 0, sizeof(sender_out));

    ret = gnutls_global_init();
    if (ret != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "gnutls_global_init failed\n");
        return 1;
    }

    ret = openssl_generate_x25519(&recip_ossl);
    if (ret != 0)
    {
        fprintf(stderr, "OpenSSL X25519 keygen failed\n");
        goto cleanup;
    }

    ret =
        openssl_privkey_to_gnutls_datum(recip_ossl.public_key, &recipe_der_key);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to convert OpenSSL private key to DER\n");
        goto cleanup;
    }

    ret = gnutls_import_from_openssl(&recipe_der_key, &recip_gnutls);
    if (ret != 0)
    {
        fprintf(stderr, "GnuTLS import failed\n");
        goto cleanup;
    }

    const unsigned char info[] = "hpke-interop-info";
    const unsigned char aad[] = "hpke-interop-aad";
    const unsigned char pt[] = "hello from openssl hpke";

    if (openssl_hpke_encap_and_seal(
            recip_ossl.public_key_raw, recip_ossl.public_key_raw_len,
            OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, info, sizeof(info) - 1, aad,
            sizeof(aad) - 1, pt, sizeof(pt) - 1, &sender_out) != 0)
    {
        fprintf(stderr, "OpenSSL HPKE encap+seal failed\n");
        goto cleanup;
    }

    unsigned char decrypted[256];
    size_t decrypted_len = sizeof(decrypted);

    gnutls_datum_t info_d = {.data = (unsigned char *)info,
                             .size = (unsigned int)(sizeof(info) - 1)};

    gnutls_datum_t enc_d = {.data = sender_out.enc,
                            .size = (unsigned int)sender_out.enclen};
    gnutls_datum_t ct_d = {.data = sender_out.ct,
                           .size = (unsigned int)sender_out.ctlen};

    if (gnutls_hpke_decap_and_open(&recip_gnutls, GNUTLS_HPKE_KEM_DHKEM_X25519,
                                   GNUTLS_HPKE_KDF_HKDF_SHA256,
                                   GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, &info_d,
                                   aad, sizeof(aad) - 1, &enc_d, &ct_d,
                                   decrypted, &decrypted_len) != 0)
    {
        fprintf(stderr, "GnuTLS decap+open failed\n");
        goto cleanup;
    }

    if (decrypted_len != (sizeof(pt) - 1) ||
        memcmp(decrypted, pt, sizeof(pt) - 1) != 0)
    {
        fprintf(stderr, "PLAINTEXT MISMATCH\n");
        goto cleanup;
    }

    printf("OK: OpenSSL seal -> GnuTLS decap+decrypt interop works(seq=0)\n");
    ret = 0;

cleanup:
    openssl_hpke_sender_out_deinit(&sender_out);
    gnutls_kp_deinit(&recip_gnutls);
    openssl_kp_deinit(&recip_ossl);

    gnutls_free(recipe_der_key.data);
    gnutls_global_deinit();

    return ret;
}
