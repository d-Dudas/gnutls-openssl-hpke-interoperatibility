#include <string.h>

#include <openssl/hpke.h>

#include "gnutls_wrapper.h"
#include "openssl_wrapper.h"

const unsigned char info[] = "hpke-interop-info";
const unsigned char aad[] = "hpke-interop-aad";
const unsigned char pt[] = "hello from openssl hpke";

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

int test_openssl_sender_gnutls_recipient(openssl_x25519_keypair_t ossl_keypair,
                                         gnutls_x25519_keypair_t gnutls_keypair)
{
    const char test_name[] = "test_openssl_sender_gnutls_recipient";
    unsigned char *enc = NULL;
    size_t enclen = 0;
    unsigned char *ct = NULL;
    size_t ctlen = 0;
    unsigned char exp[32];
    size_t explen = sizeof(exp);

    printf("[--RUN--] %s\n", test_name);
    int ret;

    ret = openssl_hpke_encap_and_seal(
        ossl_keypair.public_key_raw, ossl_keypair.public_key_raw_len,
        OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
        OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, info, sizeof(info) - 1, aad,
        sizeof(aad) - 1, pt, sizeof(pt) - 1, &enc, &enclen, &ct, &ctlen,
        (unsigned char **)&exp, &explen);
    if (ret != 0)
    {
        fprintf(stderr, "OpenSSL HPKE encap+seal failed\n");
        goto fail;
    }

    unsigned char decrypted[256];
    size_t decrypted_len = sizeof(decrypted);

    gnutls_datum_t info_d = {.data = (unsigned char *)info,
                             .size = (unsigned int)(sizeof(info) - 1)};

    gnutls_datum_t enc_d = {.data = enc, .size = (unsigned int)enclen};
    gnutls_datum_t ct_d = {.data = ct, .size = (unsigned int)ctlen};

    if (gnutls_hpke_decap_and_open(
            &gnutls_keypair, GNUTLS_HPKE_KEM_DHKEM_X25519,
            GNUTLS_HPKE_KDF_HKDF_SHA256, GNUTLS_HPKE_AEAD_CHACHA20_POLY1305,
            &info_d, aad, sizeof(aad) - 1, &enc_d, &ct_d, decrypted,
            &decrypted_len) != 0)
    {
        fprintf(stderr, "GnuTLS decap+open failed\n");
        goto fail;
    }

    if (decrypted_len != (sizeof(pt) - 1) ||
        memcmp(decrypted, pt, sizeof(pt) - 1) != 0)
    {
        fprintf(stderr, "PLAINTEXT MISMATCH\n");
        goto fail;
    }

    printf("[--PASS--] %s\n", test_name);

    ret = 0;

    goto cleanup;

fail:
    fprintf(stderr, "[--FAIL--] %s\n", test_name);

    ret = -1;

cleanup:
    OPENSSL_free(enc);
    OPENSSL_free(ct);

    return ret;
}

int main(void)
{
    int ret = 1;
    openssl_x25519_keypair_t ossl_keypair;
    gnutls_x25519_keypair_t gnutls_keypair;
    gnutls_datum_t recipient_raw = {
        .data = NULL,
        .size = 0,
    };

    memset(&ossl_keypair, 0, sizeof(ossl_keypair));
    memset(&gnutls_keypair, 0, sizeof(gnutls_keypair));

    ret = gnutls_global_init();
    if (ret != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "gnutls_global_init failed\n");
        return 1;
    }

    ret = openssl_generate_x25519(&ossl_keypair);
    if (ret != 0)
    {
        fprintf(stderr, "OpenSSL X25519 keygen failed\n");
        goto cleanup;
    }

    ret = openssl_privkey_to_gnutls_datum(ossl_keypair.public_key,
                                          &recipient_raw);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to convert OpenSSL private key to DER\n");
        goto cleanup;
    }

    ret = gnutls_import_from_openssl(&recipient_raw, &gnutls_keypair);
    if (ret != 0)
    {
        fprintf(stderr, "GnuTLS import failed\n");
        goto cleanup;
    }

    ret = test_openssl_sender_gnutls_recipient(ossl_keypair, gnutls_keypair);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    gnutls_kp_deinit(&gnutls_keypair);
    openssl_kp_deinit(&ossl_keypair);

    gnutls_free(recipient_raw.data);
    gnutls_global_deinit();

    return ret;
}
