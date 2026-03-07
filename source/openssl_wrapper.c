#include "openssl_wrapper.h"

#include <openssl/hpke.h>
#include <openssl/pem.h>

#include <string.h>

void openssl_kp_deinit(openssl_x25519_keypair_t *kp)
{
    if (!kp)
    {
        return;
    }

    if (kp->pkey)
    {
        EVP_PKEY_free(kp->pkey);
    }

    memset(kp, 0, sizeof(*kp));
}

int openssl_generate_x25519(openssl_x25519_keypair_t *out)
{
    if (!out)
    {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    int ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx)
    {
        ret = -1;
        goto cleanup;
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1)
    {
        goto cleanup;
    }

    ret = EVP_PKEY_keygen(ctx, &pkey);
    if (ret != 1)
    {
        goto cleanup;
    }

    out->pkey = pkey;
    pkey = NULL;

    out->private_key_raw_len = sizeof(out->private_key_raw);
    ret = EVP_PKEY_get_raw_private_key(out->pkey, out->private_key_raw,
                                       &out->private_key_raw_len);
    if (ret != 1)
    {
        goto cleanup;
    }

    out->public_key_raw_len = sizeof(out->public_key_raw);
    ret = EVP_PKEY_get_raw_public_key(out->pkey, out->public_key_raw,
                                      &out->public_key_raw_len);
    if (ret != 1)
    {
        goto cleanup;
    }

    if (out->private_key_raw_len != RAW_X25519_LEN ||
        out->public_key_raw_len != RAW_X25519_LEN)
    {
        ret = -1;
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }

    if (ret != 0)
    {
        openssl_kp_deinit(out);
    }

    return ret;
}

int openssl_privkey_to_pkcs8_der(EVP_PKEY *public_key, unsigned char **der,
                                 int *der_len)
{
    if (!public_key || !der || !der_len)
    {
        return -1;
    }

    int ret = -2;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char *buf = NULL;

    p8 = EVP_PKEY2PKCS8(public_key);
    if (!p8)
    {
        goto cleanup;
    }

    int len = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
    if (len <= 0)
    {
        goto cleanup;
    }

    buf = (unsigned char *)OPENSSL_malloc((size_t)len);
    if (!buf)
    {
        goto cleanup;
    }

    unsigned char *p = buf;
    int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8, &p);
    if (len2 != len)
    {
        goto cleanup;
    }

    *der = buf;
    *der_len = len;
    buf = NULL;
    ret = 0;

cleanup:
    if (p8)
        PKCS8_PRIV_KEY_INFO_free(p8);
    if (buf)
        OPENSSL_free(buf);
    return ret;
}

static int openssl_hpke_encap_and_seal_common(
    const OSSL_HPKE_SUITE suite, OSSL_HPKE_CTX *ctx,
    const unsigned char *recipient_public_key, size_t recipient_public_key_len,
    unsigned char **enc, size_t *enc_len, const unsigned char *info,
    size_t info_len, const unsigned char *plain_text, size_t plain_text_len,
    unsigned char **cipher_text, size_t *cipher_text_len,
    const unsigned char *aad, size_t aad_len, unsigned char *exp, size_t explen)
{
    int ret = -1;

    *enc_len = OSSL_HPKE_get_public_encap_size(suite);
    *enc = OPENSSL_malloc(*enc_len);
    if (!enc)
    {
        fprintf(stderr, "Failed to allocate memory for enc\n");
        goto cleanup;
    }

    ret = OSSL_HPKE_encap(ctx, *enc, enc_len, recipient_public_key,
                          recipient_public_key_len, info, info_len);
    if (ret != 1)
    {
        fprintf(stderr, "OSSL_HPKE_encap failed\n");
        goto cleanup;
    }

    *cipher_text_len = OSSL_HPKE_get_ciphertext_size(suite, plain_text_len);
    *cipher_text = OPENSSL_malloc(*cipher_text_len);
    if (!cipher_text)
    {
        fprintf(stderr, "Failed to allocate memory for cipher_text\n");
        goto cleanup;
    }

    ret = OSSL_HPKE_seal(ctx, *cipher_text, cipher_text_len, aad, aad_len,
                         plain_text, plain_text_len);
    if (ret != 1)
    {
        fprintf(stderr, "OSSL_HPKE_seal failed\n");
        goto cleanup;
    }

    ret = OSSL_HPKE_export(ctx, exp, explen,
                           (const unsigned char *)"interop-export",
                           strlen("interop-export"));
    if (ret != 1)
    {
        fprintf(stderr, "OSSL_HPKE_export failed\n");
        goto cleanup;
    }

cleanup:
    if (ret != 1)
    {
        fprintf(stderr, "Something went wrong. Freeing enc and cipher text.\n");
        OPENSSL_free(enc);
        OPENSSL_free(cipher_text);
    }

    return ret;
}

int openssl_hpke_encap_and_seal_base(
    const unsigned char *recipient_public_key, size_t recipient_public_key_len,
    uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id,
    const unsigned char *info, size_t info_len, const unsigned char *aad,
    size_t aad_len, const unsigned char *plain_text, size_t plain_text_len,
    unsigned char **enc, size_t *enc_len, unsigned char **cipher_text,
    size_t *cipher_text_len, unsigned char *exp, size_t exp_len)
{
    if (!recipient_public_key || !plain_text)
    {
        fprintf(stderr, "Invalid input: recipient_public_key and plain_text "
                        "are required\n");
        return -1;
    }

    int ret;
    OSSL_HPKE_CTX *ctx = NULL;

    OSSL_HPKE_SUITE suite;
    suite.kem_id = kem_id;
    suite.kdf_id = kdf_id;
    suite.aead_id = aead_id;

    ret = OSSL_HPKE_suite_check(suite);
    if (ret != 1)
    {
        fprintf(stderr, "Invalid HPKE suite\n");
        goto cleanup;
    }

    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_SENDER,
                            NULL, NULL);
    if (!ctx)
    {
        fprintf(stderr, "Failed to create HPKE context\n");
        goto cleanup;
    }

    ret = openssl_hpke_encap_and_seal_common(
        suite, ctx, recipient_public_key, recipient_public_key_len, enc,
        enc_len, info, info_len, plain_text, plain_text_len, cipher_text,
        cipher_text_len, aad, aad_len, exp, exp_len);
    if (ret != 1)
    {
        fprintf(stderr, "openssl_hpke_encap_and_seal_common failed\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ctx)
    {
        OSSL_HPKE_CTX_free(ctx);
    }

    return ret;
}

int openssl_hpke_encap_and_seal_psk(
    const unsigned char *recipient_public_key, size_t recipient_public_key_len,
    uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id,
    const unsigned char *psk, size_t psk_len, const unsigned char *psk_id,
    const unsigned char *info, size_t info_len, const unsigned char *aad,
    size_t aad_len, const unsigned char *plain_text, size_t plain_text_len,
    unsigned char **enc, size_t *enc_len, unsigned char **cipher_text,
    size_t *cipher_text_len, unsigned char *exp, size_t exp_len)
{
    if (!recipient_public_key || !plain_text)
    {
        fprintf(stderr, "Invalid input: recipient_public_key and plain_text "
                        "are required\n");
        return -1;
    }

    int ret;
    OSSL_HPKE_CTX *ctx = NULL;

    OSSL_HPKE_SUITE suite;
    suite.kem_id = kem_id;
    suite.kdf_id = kdf_id;
    suite.aead_id = aead_id;

    ret = OSSL_HPKE_suite_check(suite);
    if (ret != 1)
    {
        fprintf(stderr, "Invalid HPKE suite\n");
        goto cleanup;
    }

    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSK, suite, OSSL_HPKE_ROLE_SENDER,
                            NULL, NULL);
    if (!ctx)
    {
        fprintf(stderr, "Failed to create HPKE context\n");
        goto cleanup;
    }

    ret = OSSL_HPKE_CTX_set1_psk(ctx, (const char *)psk_id, psk, psk_len);
    if (ret != 1)
    {
        fprintf(stderr, "OSSL_HPKE_set_psk failed\n");
        goto cleanup;
    }

    ret = openssl_hpke_encap_and_seal_common(
        suite, ctx, recipient_public_key, recipient_public_key_len, enc,
        enc_len, info, info_len, plain_text, plain_text_len, cipher_text,
        cipher_text_len, aad, aad_len, exp, exp_len);
    if (ret != 1)
    {
        fprintf(stderr, "openssl_hpke_encap_and_seal_common failed\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ctx)
    {
        OSSL_HPKE_CTX_free(ctx);
    }

    return ret;
}
