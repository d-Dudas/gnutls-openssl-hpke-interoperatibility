#include "gnutls_wrapper.h"

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <stdio.h>
#include <string.h>

void gnutls_kp_deinit(gnutls_x25519_keypair_t *kp)
{
    if (!kp)
    {
        return;
    }

    if (kp->public_key)
    {
        gnutls_pubkey_deinit(kp->public_key);
    }

    if (kp->private_key)
    {
        gnutls_privkey_deinit(kp->private_key);
    }

    memset(kp, 0, sizeof(*kp));
}

int gnutls_import_from_openssl(const gnutls_datum_t *der,
                               gnutls_x25519_keypair_t *out)
{
    int ret;
    if (!out)
    {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    ret = gnutls_privkey_init(&out->private_key);
    if (ret != GNUTLS_E_SUCCESS)
    {
        goto cleanup;
    }

    ret = gnutls_privkey_import_x509_raw(out->private_key, der,
                                         GNUTLS_X509_FMT_DER, NULL, 0);
    if (ret != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "gnutls_privkey_import_x509_raw failed: %s\n",
                gnutls_strerror(ret));
        goto cleanup;
    }

    ret = gnutls_pubkey_init(&out->public_key);
    if (ret != GNUTLS_E_SUCCESS)
    {
        goto cleanup;
    }

    ret = gnutls_pubkey_import_privkey(out->public_key, out->private_key, 0, 0);
    if (ret != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "gnutls_pubkey_import_privkey failed: %s\n",
                gnutls_strerror(ret));
        goto cleanup;
    }

cleanup:
    if (ret != 0)
    {
        gnutls_kp_deinit(out);
    }

    return ret;
}

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000000.0 + (double)ts.tv_nsec;
}

static int gnutls_hpke_decap_and_open_common_benchmark(
    const gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
    const gnutls_datum_t *enc, gnutls_privkey_t receiver_private_key,
    const unsigned char *aad, size_t aadlen, const gnutls_datum_t *ct,
    gnutls_datum_t *plaintext, double *decap_time_us, double *open_time_us)
{
    int ret = 0;

    double start = now_ns();
    ret = gnutls_hpke_decap(ctx, info, enc, receiver_private_key);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_decap failed: rc=%d\n", ret);
        goto cleanup;
    }
    double end = now_ns();
    *decap_time_us = (end - start) / 1000.0;

    gnutls_datum_t aad_d = {.data = (unsigned char *)aad,
                            .size = (unsigned int)aadlen};

    start = now_ns();
    ret = gnutls_hpke_open(ctx, &aad_d, ct, plaintext);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_open failed: rc=%d\n", ret);
        goto cleanup;
    }
    end = now_ns();
    *open_time_us = (end - start) / 1000.0;

cleanup:
    return ret;
}

static int gnutls_hpke_decap_and_open_common(
    const gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
    const gnutls_datum_t *enc, gnutls_privkey_t receiver_private_key,
    const unsigned char *aad, size_t aadlen, const gnutls_datum_t *ct,
    gnutls_datum_t *plaintext)
{
    int ret = 0;
    ret = gnutls_hpke_decap(ctx, info, enc, receiver_private_key);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_decap failed: rc=%d\n", ret);
        goto cleanup;
    }

    gnutls_datum_t aad_d = {.data = (unsigned char *)aad,
                            .size = (unsigned int)aadlen};

    ret = gnutls_hpke_open(ctx, &aad_d, ct, plaintext);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_open failed: rc=%d\n", ret);
        goto cleanup;
    }

cleanup:
    return ret;
}

int gnutls_hpke_decap_and_open(
    const gnutls_hpke_mode_t mode, const gnutls_privkey_t receiver_private_key,
    const gnutls_pubkey_t sender_public_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *psk,
    const gnutls_datum_t *psk_id, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, const gnutls_datum_t *enc,
    const gnutls_datum_t *ciphertext, gnutls_datum_t *plaintext)
{
    int ret = 0;
    gnutls_hpke_context_t ctx = NULL;
    ret = gnutls_hpke_context_init(&ctx, mode, GNUTLS_HPKE_ROLE_RECEIVER, kem,
                                   kdf, aead);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_context_init failed: %s\n",
                gnutls_strerror(ret));
        return ret;
    }

    if (psk && psk_id)
    {
        ret = gnutls_hpke_context_set_psk(ctx, psk, psk_id);
        if (ret != 0)
        {
            fprintf(stderr, "gnutls_hpke_context_set_psk failed: %s\n",
                    gnutls_strerror(ret));
            gnutls_hpke_context_deinit(ctx);
            return ret;
        }
    }

    if (sender_public_key)
    {
        printf("Setting sender public key in HPKE context\n");
        ret = gnutls_hpke_context_set_sender_pubkey(ctx, sender_public_key);
        if (ret != 0)
        {
            fprintf(stderr,
                    "gnutls_hpke_context_set_sender_pubkey failed: %s\n",
                    gnutls_strerror(ret));
            gnutls_hpke_context_deinit(ctx);
            return ret;
        }
    }

    return gnutls_hpke_decap_and_open_common(ctx, info, enc,
                                             receiver_private_key, aad, aadlen,
                                             ciphertext, plaintext);
}

int gnutls_hpke_decap_and_open_benchmark(
    const gnutls_hpke_mode_t mode, const gnutls_privkey_t receiver_private_key,
    const gnutls_pubkey_t sender_public_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *psk,
    const gnutls_datum_t *psk_id, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, const gnutls_datum_t *enc,
    const gnutls_datum_t *ciphertext, gnutls_datum_t *plaintext,
    double *decap_time_us, double *open_time_us)
{
    int ret = 0;
    gnutls_hpke_context_t ctx = NULL;
    ret = gnutls_hpke_context_init(&ctx, mode, GNUTLS_HPKE_ROLE_RECEIVER, kem,
                                   kdf, aead);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_context_init failed: %s\n",
                gnutls_strerror(ret));
        return ret;
    }

    if (psk && psk_id)
    {
        ret = gnutls_hpke_context_set_psk(ctx, psk, psk_id);
        if (ret != 0)
        {
            fprintf(stderr, "gnutls_hpke_context_set_psk failed: %s\n",
                    gnutls_strerror(ret));
            gnutls_hpke_context_deinit(ctx);
            return ret;
        }
    }

    if (sender_public_key)
    {
        printf("Setting sender public key in HPKE context\n");
        ret = gnutls_hpke_context_set_sender_pubkey(ctx, sender_public_key);
        if (ret != 0)
        {
            fprintf(stderr,
                    "gnutls_hpke_context_set_sender_pubkey failed: %s\n",
                    gnutls_strerror(ret));
            gnutls_hpke_context_deinit(ctx);
            return ret;
        }
    }

    return gnutls_hpke_decap_and_open_common_benchmark(
        ctx, info, enc, receiver_private_key, aad, aadlen, ciphertext,
        plaintext, decap_time_us, open_time_us);
}

static int gnutls_hpke_encap_and_seal_common(
    const gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
    const gnutls_pubkey_t receiver_public_key, const unsigned char *aad,
    size_t aadlen, const gnutls_datum_t *plain_text,
    gnutls_datum_t *cipher_text, gnutls_datum_t *enc)
{
    int ret = 0;
    ret = gnutls_hpke_encap(ctx, info, enc, receiver_public_key);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_decap failed: rc=%d\n", ret);
        goto error;
    }

    gnutls_datum_t aad_d = {.data = (unsigned char *)aad,
                            .size = (unsigned int)aadlen};

    ret = gnutls_hpke_seal(ctx, &aad_d, plain_text, cipher_text);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_seal failed: rc=%d\n", ret);
        goto error;
    }

    return ret;

error:
    if (cipher_text->data)
    {
        gnutls_free(cipher_text->data);
        cipher_text->data = NULL;
        cipher_text->size = 0;
    }

    if (enc->data)
    {
        gnutls_free(enc->data);
        enc->data = NULL;
        enc->size = 0;
    }

    return ret;
}

static int gnutls_hpke_encap_and_seal_common_benchmark(
    const gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
    const gnutls_pubkey_t receiver_public_key, const unsigned char *aad,
    size_t aadlen, const gnutls_datum_t *plain_text,
    gnutls_datum_t *cipher_text, gnutls_datum_t *enc, double *encap_time_us,
    double *seal_time_us)
{
    int ret = 0;
    double start = now_ns();
    ret = gnutls_hpke_encap(ctx, info, enc, receiver_public_key);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_decap failed: rc=%d\n", ret);
        goto error;
    }
    double end = now_ns();
    *encap_time_us = (end - start) / 1000.0;

    gnutls_datum_t aad_d = {.data = (unsigned char *)aad,
                            .size = (unsigned int)aadlen};

    start = now_ns();
    ret = gnutls_hpke_seal(ctx, &aad_d, plain_text, cipher_text);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_seal failed: rc=%d\n", ret);
        goto error;
    }
    end = now_ns();
    *seal_time_us = (end - start) / 1000.0;

    return ret;

error:
    if (cipher_text->data)
    {
        gnutls_free(cipher_text->data);
        cipher_text->data = NULL;
        cipher_text->size = 0;
    }

    if (enc->data)
    {
        gnutls_free(enc->data);
        enc->data = NULL;
        enc->size = 0;
    }

    return ret;
}

int gnutls_hpke_encap_and_seal(
    const gnutls_hpke_mode_t mode, const gnutls_pubkey_t receiver_public_key,
    const gnutls_privkey_t sender_private_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *psk,
    const gnutls_datum_t *psk_id, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, gnutls_datum_t *enc,
    gnutls_datum_t *plaintext, gnutls_datum_t *ciphertext)
{
    int ret = 0;
    gnutls_hpke_context_t ctx = NULL;
    ret = gnutls_hpke_context_init(&ctx, mode, GNUTLS_HPKE_ROLE_SENDER, kem,
                                   kdf, aead);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_context_init failed: %s\n",
                gnutls_strerror(ret));
        return ret;
    }

    if (psk && psk_id)
    {
        ret = gnutls_hpke_context_set_psk(ctx, psk, psk_id);
        if (ret != 0)
        {
            fprintf(stderr, "gnutls_hpke_context_set_psk failed: %s\n",
                    gnutls_strerror(ret));
            gnutls_hpke_context_deinit(ctx);
            return ret;
        }
    }

    if (sender_private_key)
    {
        ret = gnutls_hpke_context_set_sender_privkey(ctx, sender_private_key);
        if (ret != 0)
        {
            fprintf(stderr,
                    "gnutls_hpke_context_set_sender_privkey failed: %s\n",
                    gnutls_strerror(ret));
            gnutls_hpke_context_deinit(ctx);
            return ret;
        }
    }

    return gnutls_hpke_encap_and_seal_common(ctx, info, receiver_public_key,
                                             aad, aadlen, plaintext, ciphertext,
                                             enc);
}

int gnutls_hpke_encap_and_seal_benchmark(
    const gnutls_hpke_mode_t mode, const gnutls_pubkey_t receiver_public_key,
    const gnutls_privkey_t sender_private_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *psk,
    const gnutls_datum_t *psk_id, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, gnutls_datum_t *enc,
    gnutls_datum_t *plaintext, gnutls_datum_t *ciphertext,
    double *encap_time_us, double *seal_time_us)
{
    int ret = 0;
    gnutls_hpke_context_t ctx = NULL;
    ret = gnutls_hpke_context_init(&ctx, mode, GNUTLS_HPKE_ROLE_SENDER, kem,
                                   kdf, aead);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_context_init failed: %s\n",
                gnutls_strerror(ret));
        return ret;
    }

    if (psk && psk_id)
    {
        ret = gnutls_hpke_context_set_psk(ctx, psk, psk_id);
        if (ret != 0)
        {
            fprintf(stderr, "gnutls_hpke_context_set_psk failed: %s\n",
                    gnutls_strerror(ret));
            gnutls_hpke_context_deinit(ctx);
            return ret;
        }
    }

    if (sender_private_key)
    {
        ret = gnutls_hpke_context_set_sender_privkey(ctx, sender_private_key);
        if (ret != 0)
        {
            fprintf(stderr,
                    "gnutls_hpke_context_set_sender_privkey failed: %s\n",
                    gnutls_strerror(ret));
            gnutls_hpke_context_deinit(ctx);
            return ret;
        }
    }

    return gnutls_hpke_encap_and_seal_common_benchmark(
        ctx, info, receiver_public_key, aad, aadlen, plaintext, ciphertext, enc,
        encap_time_us, seal_time_us);
}
