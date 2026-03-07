#include "gnutls_wrapper.h"
// #include "openssl_wrapper.h"

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

static int
gnutls_hpke_decap_and_open_common(const gnutls_hpke_decap_context_t *dctx,
                                  const unsigned char *aad, size_t aadlen,
                                  const gnutls_datum_t *ct,
                                  unsigned char *pt_out, size_t *pt_out_len)
{
    gnutls_datum_t key = {0};
    gnutls_datum_t base_nonce = {0};
    gnutls_datum_t exporter_secret = {0};

    int ret = 0;
    ret = gnutls_hpke_decap(dctx, &key, &base_nonce, &exporter_secret);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_decap failed: rc=%d\n", ret);
        goto cleanup;
    }

    gnutls_aead_cipher_hd_t hd;
    gnutls_datum_t key_d = {.data = key.data, .size = key.size};

    gnutls_cipher_algorithm_t gnutls_cipher = GNUTLS_CIPHER_CHACHA20_POLY1305;
    ret = gnutls_aead_cipher_init(&hd, gnutls_cipher, &key_d);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_aead_cipher_init failed: %s\n",
                gnutls_strerror(ret));
        goto cleanup;
    }

    size_t ptext_len = *pt_out_len;
    ret = gnutls_aead_cipher_decrypt(hd, base_nonce.data, base_nonce.size, aad,
                                     aadlen, 16, ct->data, ct->size, pt_out,
                                     &ptext_len);
    gnutls_aead_cipher_deinit(hd);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_aead_cipher_decrypt failed: %s\n",
                gnutls_strerror(ret));
        goto cleanup;
    }

    *pt_out_len = ptext_len;

cleanup:
    gnutls_free(key.data);
    gnutls_free(base_nonce.data);
    gnutls_free(exporter_secret.data);
    return ret;
}

int gnutls_hpke_decap_and_open_base(
    const gnutls_privkey_t receiver_private_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, const gnutls_datum_t *enc,
    const gnutls_datum_t *ct, unsigned char *pt_out, size_t *pt_out_len)
{
    gnutls_hpke_decap_context_t dctx = {.kem = kem,
                                        .kdf = kdf,
                                        .aead = aead,
                                        .info = info,
                                        .psk = NULL,
                                        .psk_id = NULL,
                                        .enc = enc,
                                        .receiver_privkey =
                                            receiver_private_key,
                                        .sender_pubkey = NULL};

    return gnutls_hpke_decap_and_open_common(&dctx, aad, aadlen, ct, pt_out,
                                             pt_out_len);
}

int gnutls_hpke_decap_and_open_psk(
    const gnutls_privkey_t receiver_private_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *psk,
    const gnutls_datum_t *psk_id, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, const gnutls_datum_t *enc,
    const gnutls_datum_t *ct, unsigned char *pt_out, size_t *pt_out_len)
{
    gnutls_hpke_decap_context_t dctx = {.kem = kem,
                                        .kdf = kdf,
                                        .aead = aead,
                                        .info = info,
                                        .psk = psk,
                                        .psk_id = psk_id,
                                        .enc = enc,
                                        .receiver_privkey =
                                            receiver_private_key,
                                        .sender_pubkey = NULL};

    return gnutls_hpke_decap_and_open_common(&dctx, aad, aadlen, ct, pt_out,
                                             pt_out_len);
}

int gnutls_hpke_decap_and_open_auth(
    const gnutls_privkey_t receiver_private_key,
    const gnutls_pubkey_t sender_public_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, const gnutls_datum_t *enc,
    const gnutls_datum_t *ct, unsigned char *pt_out, size_t *pt_out_len)
{
    gnutls_hpke_decap_context_t dctx = {.kem = kem,
                                        .kdf = kdf,
                                        .aead = aead,
                                        .info = info,
                                        .psk = NULL,
                                        .psk_id = NULL,
                                        .enc = enc,
                                        .receiver_privkey =
                                            receiver_private_key,
                                        .sender_pubkey = sender_public_key};

    return gnutls_hpke_decap_and_open_common(&dctx, aad, aadlen, ct, pt_out,
                                             pt_out_len);
}

int gnutls_hpke_decap_and_open(
    const gnutls_privkey_t receiver_private_key,
    const gnutls_pubkey_t sender_public_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *psk,
    const gnutls_datum_t *psk_id, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, const gnutls_datum_t *enc,
    const gnutls_datum_t *ct, unsigned char *pt_out, size_t *pt_out_len)
{
    gnutls_hpke_decap_context_t dctx = {.kem = kem,
                                        .kdf = kdf,
                                        .aead = aead,
                                        .info = info,
                                        .psk = psk,
                                        .psk_id = psk_id,
                                        .enc = enc,
                                        .receiver_privkey =
                                            receiver_private_key,
                                        .sender_pubkey = sender_public_key};

    return gnutls_hpke_decap_and_open_common(&dctx, aad, aadlen, ct, pt_out,
                                             pt_out_len);
}

static int gnutls_hpke_encap_and_seal_common(
    const gnutls_hpke_encap_context_t *ectx, const unsigned char *aad,
    size_t aadlen, const gnutls_datum_t *plain_text,
    gnutls_datum_t *cipher_text, gnutls_datum_t *enc)
{
    gnutls_datum_t key = {0};
    gnutls_datum_t base_nonce = {0};
    gnutls_datum_t exporter_secret = {0};

    int ret = 0;
    ret = gnutls_hpke_encap(ectx, enc, &key, &base_nonce, &exporter_secret);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_hpke_decap failed: rc=%d\n", ret);
        goto cleanup;
    }

    gnutls_aead_cipher_hd_t hd;
    gnutls_datum_t key_d = {.data = key.data, .size = key.size};

    gnutls_cipher_algorithm_t gnutls_cipher = GNUTLS_CIPHER_CHACHA20_POLY1305;
    ret = gnutls_aead_cipher_init(&hd, gnutls_cipher, &key_d);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_aead_cipher_init failed: %s\n",
                gnutls_strerror(ret));
        goto cleanup;
    }

    size_t cipher_text_len = plain_text->size + 16;
    cipher_text->data = gnutls_malloc(cipher_text_len);
    if (!cipher_text->data)
    {
        fprintf(stderr, "gnutls_malloc failed\n");
        ret = -1;
        goto cleanup;
    }
    cipher_text->size = (unsigned int)cipher_text_len;

    ret = gnutls_aead_cipher_encrypt(
        hd, base_nonce.data, base_nonce.size, aad, aadlen, 16, plain_text->data,
        plain_text->size, cipher_text->data, &cipher_text_len);
    gnutls_aead_cipher_deinit(hd);
    if (ret != 0)
    {
        fprintf(stderr, "gnutls_aead_cipher_encrypt failed: %s\n",
                gnutls_strerror(ret));
        goto cleanup;
    }

    cipher_text->size = (unsigned int)cipher_text_len;

cleanup:
    gnutls_free(key.data);
    gnutls_free(base_nonce.data);
    gnutls_free(exporter_secret.data);
    return ret;
}

int gnutls_hpke_encap_and_seal(
    const gnutls_pubkey_t receiver_public_key,
    const gnutls_privkey_t sender_private_key, gnutls_hpke_kem_t kem,
    gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead, const gnutls_datum_t *psk,
    const gnutls_datum_t *psk_id, const gnutls_datum_t *info,
    const unsigned char *aad, size_t aadlen, gnutls_datum_t *enc,
    gnutls_datum_t *plain_text, gnutls_datum_t *cipher_text)
{
    gnutls_hpke_encap_context_t ectx = {.kem = kem,
                                        .kdf = kdf,
                                        .aead = aead,
                                        .info = info,
                                        .psk = psk,
                                        .psk_id = psk_id,
                                        .receiver_pubkey = receiver_public_key,
                                        .sender_privkey = sender_private_key};

    return gnutls_hpke_encap_and_seal_common(&ectx, aad, aadlen, plain_text,
                                             cipher_text, enc);
}
