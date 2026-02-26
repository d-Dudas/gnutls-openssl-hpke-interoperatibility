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

    if (kp->public_key)
    {
        EVP_PKEY_free(kp->public_key);
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

    out->public_key = pkey;
    pkey = NULL;

    out->private_key_raw_len = sizeof(out->private_key_raw);
    ret = EVP_PKEY_get_raw_private_key(out->public_key, out->private_key_raw,
                                       &out->private_key_raw_len);
    if (ret != 1)
    {
        goto cleanup;
    }

    out->public_key_raw_len = sizeof(out->public_key_raw);
    ret = EVP_PKEY_get_raw_public_key(out->public_key, out->public_key_raw,
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

void openssl_hpke_sender_out_deinit(openssl_hpke_sender_out_t *o)
{
    if (!o)
    {
        return;
    }

    OPENSSL_free(o->enc);
    OPENSSL_free(o->ct);

    memset(o, 0, sizeof(*o));
}

int openssl_hpke_encap_and_seal(const unsigned char *recip_pub,
                                size_t recip_publen, uint16_t kem_id,
                                uint16_t kdf_id, uint16_t aead_id,
                                const unsigned char *info, size_t infolen,
                                const unsigned char *aad, size_t aadlen,
                                const unsigned char *pt, size_t ptlen,
                                openssl_hpke_sender_out_t *out)
{
    if (!recip_pub || !out || !pt)
    {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    int ret;
    OSSL_HPKE_CTX *ctx = NULL;

    OSSL_HPKE_SUITE suite;
    suite.kem_id = kem_id;
    suite.kdf_id = kdf_id;
    suite.aead_id = aead_id;

    ret = OSSL_HPKE_suite_check(suite);
    if (ret != 1)
    {
        goto cleanup;
    }

    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_SENDER,
                            NULL, NULL);
    if (!ctx)
    {
        goto cleanup;
    }

    out->enclen = OSSL_HPKE_get_public_encap_size(suite);
    out->enc = OPENSSL_malloc(out->enclen);
    if (!out->enc)
    {
        goto cleanup;
    }

    ret = OSSL_HPKE_encap(ctx, out->enc, &out->enclen, recip_pub, recip_publen,
                          info, infolen);
    if (ret != 1)
    {
        goto cleanup;
    }

    out->ctlen = OSSL_HPKE_get_ciphertext_size(suite, ptlen);
    out->ct = OPENSSL_malloc(out->ctlen);
    if (!out->ct)
    {
        goto cleanup;
    }

    ret = OSSL_HPKE_seal(ctx, out->ct, &out->ctlen, aad, aadlen, pt, ptlen);
    if (ret != 1)
    {
        goto cleanup;
    }

    out->explen = sizeof(out->exp);
    ret = OSSL_HPKE_export(ctx, out->exp, out->explen,
                           (const unsigned char *)"interop-export",
                           strlen("interop-export"));

    if (ret != 1)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ctx)
    {
        OSSL_HPKE_CTX_free(ctx);
    }

    if (ret != 0)
    {
        openssl_hpke_sender_out_deinit(out);
    }

    return ret;
}
