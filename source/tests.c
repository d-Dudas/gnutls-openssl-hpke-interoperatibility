#include "tests.h"

#include <openssl/hpke.h>

#include <string.h>

static const unsigned char info[] = "hpke-interop-info";
static const unsigned char aad[] = "hpke-interop-aad";
static const unsigned char pt[] = "hello from openssl hpke";
// static const unsigned char psk[] = "some-32-byte-psk-value-123456789";
// static const unsigned char psk_id[] = "hpke-interop-psk-id";

int test_openssl_sender_gnutls_recipient(
    const openssl_x25519_keypair_t *ossl_keypair,
    const gnutls_x25519_keypair_t *gnutls_keypair)
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
        ossl_keypair->public_key_raw, ossl_keypair->public_key_raw_len,
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

    if (gnutls_hpke_decap_and_open(gnutls_keypair, GNUTLS_HPKE_KEM_DHKEM_X25519,
                                   GNUTLS_HPKE_KDF_HKDF_SHA256,
                                   GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, &info_d,
                                   aad, sizeof(aad) - 1, &enc_d, &ct_d,
                                   decrypted, &decrypted_len) != 0)
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
