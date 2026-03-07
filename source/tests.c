#include "tests.h"
#include "gnutls_wrapper.h"
#include "openssl_wrapper.h"

#include <openssl/hpke.h>

#include <string.h>

#define PRINT_RUN() printf("[--RUN--] %s\n", __func__)
#define PRINT_PASS() printf("[--PASS--] %s\n", __func__)
#define PRINT_FAIL() printf("[--FAIL--] %s\n", __func__)

static const unsigned char info[] = "hpke-interop-info";
static const unsigned char aad[] = "hpke-interop-aad";
static const unsigned char pt[] = "hello from openssl hpke";
static const unsigned char psk[] = "some-32-byte-psk-value-123456789";
static const unsigned char psk_id[] = "hpke-interop-psk-id";

int test_openssl_sender_gnutls_recipient_base(
    const unsigned char *recipient_public_key_raw,
    const size_t recipient_public_key_raw_len,
    const gnutls_privkey_t recipient_private_key)
{
    PRINT_RUN();

    unsigned char *enc = NULL;
    size_t enclen = 0;
    unsigned char *ct = NULL;
    size_t ctlen = 0;
    unsigned char exp[32];
    size_t explen = sizeof(exp);

    int ret;

    ret = openssl_hpke_encap_and_seal_base(
        recipient_public_key_raw, recipient_public_key_raw_len,
        OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
        OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, info, sizeof(info) - 1, aad,
        sizeof(aad) - 1, pt, sizeof(pt) - 1, &enc, &enclen, &ct, &ctlen, exp,
        explen);
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

    if (gnutls_hpke_decap_and_open_base(
            recipient_private_key, GNUTLS_HPKE_KEM_DHKEM_X25519,
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

    PRINT_PASS();

    ret = 0;

    goto cleanup;

fail:
    PRINT_FAIL();

    ret = -1;

cleanup:
    OPENSSL_free(enc);
    OPENSSL_free(ct);

    return ret;
}

int test_openssl_sender_gnutls_recipient_psk(
    const unsigned char *recipient_public_key_raw,
    const size_t recipient_public_key_raw_len,
    const gnutls_privkey_t recipient_private_key)
{
    PRINT_RUN();

    unsigned char *enc = NULL;
    size_t enclen = 0;
    unsigned char *ct = NULL;
    size_t ctlen = 0;
    unsigned char exp[32];
    size_t explen = sizeof(exp);

    int ret;

    ret = openssl_hpke_encap_and_seal_psk(
        recipient_public_key_raw, recipient_public_key_raw_len,
        OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
        OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, psk, sizeof(psk), psk_id, info,
        sizeof(info) - 1, aad, sizeof(aad) - 1, pt, sizeof(pt) - 1, &enc,
        &enclen, &ct, &ctlen, exp, explen);
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

    gnutls_datum_t psk_d = {.data = (unsigned char *)psk,
                            .size = (unsigned int)sizeof(psk)};
    gnutls_datum_t psk_id_d = {.data = (unsigned char *)psk_id,
                               .size = (unsigned int)sizeof(psk_id) - 1};

    if (gnutls_hpke_decap_and_open_psk(
            recipient_private_key, GNUTLS_HPKE_KEM_DHKEM_X25519,
            GNUTLS_HPKE_KDF_HKDF_SHA256, GNUTLS_HPKE_AEAD_CHACHA20_POLY1305,
            &psk_d, &psk_id_d, &info_d, aad, sizeof(aad) - 1, &enc_d, &ct_d,
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

    PRINT_PASS();

    ret = 0;

    goto cleanup;

fail:
    PRINT_FAIL();

    ret = -1;

cleanup:
    OPENSSL_free(enc);
    OPENSSL_free(ct);

    return ret;
}
