#include "gnutls-wrapper.h"
#include "constants.h"

#include <gnutls/abstract.h>
#include <gnutls/hpke.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

typedef struct hpke_test_encryption_parameters_st
{
    size_t sequence_number;
    gnutls_datum_t plaintext;
    gnutls_datum_t aad;
    gnutls_datum_t expected_ciphertext;
} hpke_test_encryption_parameters_st;

typedef struct hpke_test_exporter_parameters_st
{
    gnutls_datum_t exporter_context;
    size_t exporter_length;
    gnutls_datum_t expected_exporter_value;
} hpke_test_exporter_parameters_st;

typedef struct hpke_test_parameters_st
{
    gnutls_hpke_mode_t mode;
    gnutls_hpke_kem_t kem;
    gnutls_hpke_kdf_t kdf;
    gnutls_hpke_aead_t aead;
    gnutls_datum_t ikmE;
    gnutls_datum_t ikmR;
    gnutls_datum_t *ikmS;
    gnutls_datum_t info;
    gnutls_datum_t *psk;
    gnutls_datum_t *psk_id;
    gnutls_datum_t expected_enc;
    hpke_test_encryption_parameters_st *encryption_parameters;
    size_t num_encryption_parameters;
    hpke_test_exporter_parameters_st *exporter_parameters;
    size_t num_exporter_parameters;
} hpke_test_parameters_st;

static void test_hpke(benchmarker_context *ctx,
                      const hpke_test_parameters_st *params)
{
    int ret;
    gnutls_privkey_t skR = NULL;
    gnutls_pubkey_t pkR = NULL;
    gnutls_privkey_t skS = NULL;
    gnutls_pubkey_t pkS = NULL;

    gnutls_hpke_context_t sender_ctx = NULL;
    gnutls_hpke_context_t receiver_ctx = NULL;

    gnutls_datum_t enc = {NULL, 0};
    gnutls_datum_t plaintext_out = {NULL, 0};
    gnutls_datum_t ciphertext_out = {NULL, 0};
    gnutls_datum_t exporter_out = {NULL, 0};

    double starttime, endtime;

    ret = gnutls_hpke_context_init(&sender_ctx, params->mode,
                                   GNUTLS_HPKE_ROLE_SENDER, params->kem,
                                   params->kdf, params->aead);
    if (ret < 0)
    {
        fail("gnutls_hpke_context_init (mode: %d, kem: %d, kdf: %d, aead: %d) "
             "failed: %s\n",
             params->mode, params->kem, params->kdf, params->aead,
             gnutls_strerror(ret));
        goto cleanup;
    }

    ret = gnutls_hpke_context_set_ikme(sender_ctx, &params->ikmE);
    if (ret < 0)
    {
        fail("gnutls_hpke_context_set_ikme (mode %d, kem: %d, kdf: %d, aead: "
             "%d) failed: %s\n",
             params->mode, params->kem, params->kdf, params->aead,
             gnutls_strerror(ret));
        goto cleanup;
    }

    if (params->psk != NULL && params->psk_id != NULL)
    {
        ret = gnutls_hpke_context_set_psk(sender_ctx, params->psk,
                                          params->psk_id);
        if (ret < 0)
        {
            fail("gnutls_hpke_context_set_psk (mode %d, kem: %d, kdf: %d, "
                 "aead: %d) failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }
    }

    if (params->ikmS != NULL)
    {
        ret =
            gnutls_hpke_generate_keypair(params->kem, params->ikmS, &skS, &pkS);
        if (ret < 0)
        {
            fail("gnutls_hpke_generate_keypair (mode %d, kem: %d, kdf: %d, "
                 "aead: %d) failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }

        ret = gnutls_hpke_context_set_sender_privkey(sender_ctx, skS);
        if (ret < 0)
        {
            fail("gnutls_hpke_context_set_sender_privkey (mode %d, kem: %d, "
                 "kdf: %d, aead: %d) failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }
    }

    starttime = benchmarker_get_now();
    ret = gnutls_hpke_generate_keypair(params->kem, &params->ikmR, &skR, &pkR);
    endtime = benchmarker_get_now();

    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_GNUTLS,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_KEYGEN, starttime,
                           endtime);
    if (ret < 0)
    {
        fail("gnutls_hpke_generate_keypair (mode %d, kem: %d, kdf: %d, aead: "
             "%d) failed: %s\n",
             params->mode, params->kem, params->kdf, params->aead,
             gnutls_strerror(ret));
        goto cleanup;
    }

    starttime = benchmarker_get_now();
    ret = gnutls_hpke_encap(sender_ctx, &params->info, &enc, pkR);
    endtime = benchmarker_get_now();
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_GNUTLS,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_ENCAPS, starttime,
                           endtime);
    if (ret < 0)
    {
        fail("gnutls_hpke_encap (mode %d, kem: %d, kdf: %d, aead: %d) failed: "
             "%s\n",
             params->mode, params->kem, params->kdf, params->aead,
             gnutls_strerror(ret));
        goto cleanup;
    }

    if (params->expected_enc.size != enc.size ||
        memcmp(params->expected_enc.data, enc.data, enc.size) != 0)
    {
        fail("enc does not match expected value (mode %d, kem: %d, kdf: %d, "
             "aead: %d)\n",
             params->mode, params->kem, params->kdf, params->aead);
        goto cleanup;
    }

    ret = gnutls_hpke_context_init(&receiver_ctx, params->mode,
                                   GNUTLS_HPKE_ROLE_RECEIVER, params->kem,
                                   params->kdf, params->aead);
    if (ret < 0)
    {
        fail("gnutls_context_init (mode %d, kem: %d, kdf: %d, aead: %d) "
             "failed: %s\n",
             params->mode, params->kem, params->kdf, params->aead,
             gnutls_strerror(ret));
        goto cleanup;
    }

    if (params->psk != NULL && params->psk_id != NULL)
    {
        ret = gnutls_hpke_context_set_psk(receiver_ctx, params->psk,
                                          params->psk_id);
        if (ret < 0)
        {
            fail("gnutls_hpke_context_set_psk (mode %d, kem: %d, kdf: %d, "
                 "aead: %d) failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }
    }

    if (params->ikmS != NULL)
    {
        ret = gnutls_hpke_context_set_sender_pubkey(receiver_ctx, pkS);
        if (ret < 0)
        {
            fail("gnutls_hpke_context_set_sender_pubkey (mode %d, kem: %d, "
                 "kdf: %d, aead: %d) failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }
    }

    starttime = benchmarker_get_now();
    ret = gnutls_hpke_decap(receiver_ctx, &params->info, &enc, skR);
    endtime = benchmarker_get_now();
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_GNUTLS,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_DECAPS, starttime,
                           endtime);
    if (ret < 0)
    {
        fail("gnutls_hpke_decap (mode %d, kem: %d, kdf: %d, aead: %d) failed: "
             "%s\n",
             params->mode, params->kem, params->kdf, params->aead,
             gnutls_strerror(ret));
        goto cleanup;
    }

    double total_seal_time = 0;
    double total_open_time = 0;
    for (size_t i = 0; i < params->num_encryption_parameters; i++)
    {
        hpke_test_encryption_parameters_st *enc_params =
            &params->encryption_parameters[i];

        starttime = benchmarker_get_now();
        ret = gnutls_hpke_seal(sender_ctx, &enc_params->aad,
                               &enc_params->plaintext, &ciphertext_out);
        endtime = benchmarker_get_now();
        total_seal_time += (endtime - starttime);
        if (ret < 0)
        {
            fail("gnutls_hpke_seal (mode %d, kem: %d, kdf: %d, aead: %d) "
                 "failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }

        if (enc_params->expected_ciphertext.size != ciphertext_out.size ||
            memcmp(enc_params->expected_ciphertext.data, ciphertext_out.data,
                   ciphertext_out.size) != 0)
        {
            fail("ciphertext does not match expected value (mode %d, kem: %d, "
                 "kdf: %d, aead: %d)\n",
                 params->mode, params->kem, params->kdf, params->aead);
            goto cleanup;
        }

        starttime = benchmarker_get_now();
        ret = gnutls_hpke_open(receiver_ctx, &enc_params->aad, &ciphertext_out,
                               &plaintext_out);
        endtime = benchmarker_get_now();
        total_open_time += (endtime - starttime);
        if (ret < 0)
        {
            fail("gnutls_hpke_open (mode %d, kem: %d, kdf: %d, aead: %d) "
                 "failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }

        if (enc_params->plaintext.size != plaintext_out.size ||
            memcmp(enc_params->plaintext.data, plaintext_out.data,
                   plaintext_out.size) != 0)
        {
            fail("decrypted plaintext does not match original plaintext (mode "
                 "%d, kem: %d, kdf: %d, aead: %d)\n",
                 params->mode, params->kem, params->kdf, params->aead);
            goto cleanup;
        }

        uint64_t seq;
        ret = gnutls_hpke_get_seq(receiver_ctx, &seq);
        if (ret < 0)
        {
            fail("gnutls_hpke_get_seq (mode %d, kem: %d, kdf: %d, aead: %d) "
                 "failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }

        if (seq != enc_params->sequence_number + 1)
        {
            fail("sequence number does not match expected value (mode %d, kem: "
                 "%d, kdf: %d, aead: %d)\n",
                 params->mode, params->kem, params->kdf, params->aead);
            goto cleanup;
        }

        gnutls_free(ciphertext_out.data);
        ciphertext_out.data = NULL;
        gnutls_free(plaintext_out.data);
        plaintext_out.data = NULL;
    }

    total_seal_time /= params->num_encryption_parameters;
    total_open_time /= params->num_encryption_parameters;
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_GNUTLS,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_SEAL, 0,
                           total_seal_time);
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_GNUTLS,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_OPEN, 0,
                           total_open_time);

    for (size_t i = 0; i < params->num_exporter_parameters; i++)
    {
        hpke_test_exporter_parameters_st *exp_params =
            &params->exporter_parameters[i];
        ret = gnutls_hpke_export(sender_ctx, &exp_params->exporter_context, 32,
                                 &exporter_out);
        if (ret < 0)
        {
            fail("gnutls_hpke_export (mode %d, kem: %d, kdf: %d, aead: %d) "
                 "failed: %s\n",
                 params->mode, params->kem, params->kdf, params->aead,
                 gnutls_strerror(ret));
            goto cleanup;
        }

        if (exp_params->expected_exporter_value.size != exporter_out.size ||
            memcmp(exp_params->expected_exporter_value.data, exporter_out.data,
                   exporter_out.size) != 0)
        {
            fail("exported value does not match expected value (mode %d, kem: "
                 "%d, kdf: %d, aead: %d)\n",
                 params->mode, params->kem, params->kdf, params->aead);
            goto cleanup;
        }

        gnutls_free(exporter_out.data);
        exporter_out.data = NULL;
    }

cleanup:
    gnutls_privkey_deinit(skR);
    gnutls_pubkey_deinit(pkR);
    gnutls_privkey_deinit(skS);
    gnutls_pubkey_deinit(pkS);
    gnutls_hpke_context_deinit(sender_ctx);
    gnutls_hpke_context_deinit(receiver_ctx);

    if (enc.data != NULL)
    {
        gnutls_free(enc.data);
    }

    if (plaintext_out.data != NULL)
    {
        gnutls_free(plaintext_out.data);
    }

    if (ciphertext_out.data != NULL)
    {
        gnutls_free(ciphertext_out.data);
    }

    if (exporter_out.data != NULL)
    {
        gnutls_free(exporter_out.data);
    }
}

static void rfc9180_a11(benchmarker_context *ctx)
{
    hpke_test_encryption_parameters_st enc_params[] = {
        {.sequence_number = 0,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq0_aad, sizeof(seq0_aad)},
         .expected_ciphertext = {a11_seq0_expected_ct,
                                 sizeof(a11_seq0_expected_ct)}},
        {.sequence_number = 1,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq1_aad, sizeof(seq1_aad)},
         .expected_ciphertext = {a11_seq1_expected_ct,
                                 sizeof(a11_seq1_expected_ct)}},
        {.sequence_number = 2,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq2_aad, sizeof(seq2_aad)},
         .expected_ciphertext = {a11_seq2_expected_ct,
                                 sizeof(a11_seq2_expected_ct)}}};

    hpke_test_exporter_parameters_st exporter_params[] = {
        {.exporter_context = {exporter_context_1, sizeof(exporter_context_1)},
         .exporter_length = sizeof(a11_expected_exporter_value_1),
         .expected_exporter_value = {a11_expected_exporter_value_1,
                                     sizeof(a11_expected_exporter_value_1)}},
        {.exporter_context = {exporter_context_2, sizeof(exporter_context_2)},
         .exporter_length = sizeof(a11_expected_exporter_value_2),
         .expected_exporter_value = {a11_expected_exporter_value_2,
                                     sizeof(a11_expected_exporter_value_2)}},
        {.exporter_context = {exporter_context_3, sizeof(exporter_context_3)},
         .exporter_length = sizeof(a11_expected_exporter_value_3),
         .expected_exporter_value = {a11_expected_exporter_value_3,
                                     sizeof(a11_expected_exporter_value_3)}}};

    hpke_test_parameters_st params = {
        .mode = GNUTLS_HPKE_MODE_BASE,
        .kem = GNUTLS_HPKE_KEM_DHKEM_X25519,
        .kdf = GNUTLS_HPKE_KDF_HKDF_SHA256,
        .aead = GNUTLS_HPKE_AEAD_AES_128_GCM,
        .ikmE = {a11_ikmE, sizeof(a11_ikmE)},
        .ikmR = {a11_ikmR, sizeof(a11_ikmR)},
        .ikmS = NULL,
        .info = {info, sizeof(info)},
        .psk = NULL,
        .psk_id = NULL,
        .expected_enc = {a11_expected_enc, sizeof(a11_expected_enc)},
        .encryption_parameters = enc_params,
        .num_encryption_parameters = sizeof(enc_params) / sizeof(enc_params[0]),
        .exporter_parameters = exporter_params,
        .num_exporter_parameters =
            sizeof(exporter_params) / sizeof(exporter_params[0])};

    test_hpke(ctx, &params);
}

static void rfc9180_a12(benchmarker_context *ctx)
{
    hpke_test_encryption_parameters_st enc_params[] = {
        {.sequence_number = 0,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq0_aad, sizeof(seq0_aad)},
         .expected_ciphertext = {a12_seq0_expected_ct,
                                 sizeof(a12_seq0_expected_ct)}},
        {.sequence_number = 1,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq1_aad, sizeof(seq1_aad)},
         .expected_ciphertext = {a12_seq1_expected_ct,
                                 sizeof(a12_seq1_expected_ct)}},
        {.sequence_number = 2,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq2_aad, sizeof(seq2_aad)},
         .expected_ciphertext = {a12_seq2_expected_ct,
                                 sizeof(a12_seq2_expected_ct)}}};

    hpke_test_exporter_parameters_st exporter_params[] = {
        {.exporter_context = {exporter_context_1, sizeof(exporter_context_1)},
         .exporter_length = sizeof(a12_expected_exporter_value_1),
         .expected_exporter_value = {a12_expected_exporter_value_1,
                                     sizeof(a12_expected_exporter_value_1)}},
        {.exporter_context = {exporter_context_2, sizeof(exporter_context_2)},
         .exporter_length = sizeof(a12_expected_exporter_value_2),
         .expected_exporter_value = {a12_expected_exporter_value_2,
                                     sizeof(a12_expected_exporter_value_2)}},
        {.exporter_context = {exporter_context_3, sizeof(exporter_context_3)},
         .exporter_length = sizeof(a12_expected_exporter_value_3),
         .expected_exporter_value = {a12_expected_exporter_value_3,
                                     sizeof(a12_expected_exporter_value_3)}}};

    gnutls_datum_t psk_datum = {psk, sizeof(psk)};
    gnutls_datum_t psk_id_datum = {psk_id, sizeof(psk_id)};
    hpke_test_parameters_st params = {
        .mode = GNUTLS_HPKE_MODE_PSK,
        .kem = GNUTLS_HPKE_KEM_DHKEM_X25519,
        .kdf = GNUTLS_HPKE_KDF_HKDF_SHA256,
        .aead = GNUTLS_HPKE_AEAD_AES_128_GCM,
        .ikmE = {a12_ikmE, sizeof(a12_ikmE)},
        .ikmR = {a12_ikmR, sizeof(a12_ikmR)},
        .ikmS = NULL,
        .info = {info, sizeof(info)},
        .psk = &psk_datum,
        .psk_id = &psk_id_datum,
        .expected_enc = {a12_expected_enc, sizeof(a12_expected_enc)},
        .encryption_parameters = enc_params,
        .num_encryption_parameters = sizeof(enc_params) / sizeof(enc_params[0]),
        .exporter_parameters = exporter_params,
        .num_exporter_parameters =
            sizeof(exporter_params) / sizeof(exporter_params[0])};

    test_hpke(ctx, &params);
}

static void rfc9180_a13(benchmarker_context *ctx)
{
    hpke_test_encryption_parameters_st enc_params[] = {
        {.sequence_number = 0,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq0_aad, sizeof(seq0_aad)},
         .expected_ciphertext = {a13_seq0_expected_ct,
                                 sizeof(a13_seq0_expected_ct)}},
        {.sequence_number = 1,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq1_aad, sizeof(seq1_aad)},
         .expected_ciphertext = {a13_seq1_expected_ct,
                                 sizeof(a13_seq1_expected_ct)}},
        {.sequence_number = 2,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq2_aad, sizeof(seq2_aad)},
         .expected_ciphertext = {a13_seq2_expected_ct,
                                 sizeof(a13_seq2_expected_ct)}}};

    hpke_test_exporter_parameters_st exporter_params[] = {
        {.exporter_context = {exporter_context_1, sizeof(exporter_context_1)},
         .exporter_length = sizeof(a13_expected_exporter_value_1),
         .expected_exporter_value = {a13_expected_exporter_value_1,
                                     sizeof(a13_expected_exporter_value_1)}},
        {.exporter_context = {exporter_context_2, sizeof(exporter_context_2)},
         .exporter_length = sizeof(a13_expected_exporter_value_2),
         .expected_exporter_value = {a13_expected_exporter_value_2,
                                     sizeof(a13_expected_exporter_value_2)}},
        {.exporter_context = {exporter_context_3, sizeof(exporter_context_3)},
         .exporter_length = sizeof(a13_expected_exporter_value_3),
         .expected_exporter_value = {a13_expected_exporter_value_3,
                                     sizeof(a13_expected_exporter_value_3)}}};

    gnutls_datum_t ikmS_datum = {a13_ikmS, sizeof(a13_ikmS)};
    hpke_test_parameters_st params = {
        .mode = GNUTLS_HPKE_MODE_AUTH,
        .kem = GNUTLS_HPKE_KEM_DHKEM_X25519,
        .kdf = GNUTLS_HPKE_KDF_HKDF_SHA256,
        .aead = GNUTLS_HPKE_AEAD_AES_128_GCM,
        .ikmE = {a13_ikmE, sizeof(a13_ikmE)},
        .ikmR = {a13_ikmR, sizeof(a13_ikmR)},
        .ikmS = &ikmS_datum,
        .info = {info, sizeof(info)},
        .psk = NULL,
        .psk_id = NULL,
        .expected_enc = {a13_expected_enc, sizeof(a13_expected_enc)},
        .encryption_parameters = enc_params,
        .num_encryption_parameters = sizeof(enc_params) / sizeof(enc_params[0]),
        .exporter_parameters = exporter_params,
        .num_exporter_parameters =
            sizeof(exporter_params) / sizeof(exporter_params[0])};

    test_hpke(ctx, &params);
}

static void rfc9180_a14(benchmarker_context *ctx)
{
    hpke_test_encryption_parameters_st enc_params[] = {
        {.sequence_number = 0,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq0_aad, sizeof(seq0_aad)},
         .expected_ciphertext = {a14_seq0_expected_ct,
                                 sizeof(a14_seq0_expected_ct)}},
        {.sequence_number = 1,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq1_aad, sizeof(seq1_aad)},
         .expected_ciphertext = {a14_seq1_expected_ct,
                                 sizeof(a14_seq1_expected_ct)}},
        {.sequence_number = 2,
         .plaintext = {plaintext, sizeof(plaintext)},
         .aad = {seq2_aad, sizeof(seq2_aad)},
         .expected_ciphertext = {a14_seq2_expected_ct,
                                 sizeof(a14_seq2_expected_ct)}}};

    hpke_test_exporter_parameters_st exporter_params[] = {
        {.exporter_context = {exporter_context_1, sizeof(exporter_context_1)},
         .exporter_length = sizeof(a14_expected_exporter_value1),
         .expected_exporter_value = {a14_expected_exporter_value1,
                                     sizeof(a14_expected_exporter_value1)}},
        {.exporter_context = {exporter_context_2, sizeof(exporter_context_2)},
         .exporter_length = sizeof(a14_expected_exporter_value2),
         .expected_exporter_value = {a14_expected_exporter_value2,
                                     sizeof(a14_expected_exporter_value2)}},
        {.exporter_context = {exporter_context_3, sizeof(exporter_context_3)},
         .exporter_length = sizeof(a14_expected_exporter_value3),
         .expected_exporter_value = {a14_expected_exporter_value3,
                                     sizeof(a14_expected_exporter_value3)}}};

    gnutls_datum_t ikmS_datum = {a14_ikmS, sizeof(a14_ikmS)};
    gnutls_datum_t psk_datum = {psk, sizeof(psk)};
    gnutls_datum_t psk_id_datum = {psk_id, sizeof(psk_id)};
    hpke_test_parameters_st params = {
        .mode = GNUTLS_HPKE_MODE_AUTH_PSK,
        .kem = GNUTLS_HPKE_KEM_DHKEM_X25519,
        .kdf = GNUTLS_HPKE_KDF_HKDF_SHA256,
        .aead = GNUTLS_HPKE_AEAD_AES_128_GCM,
        .ikmE = {a14_ikmE, sizeof(a14_ikmE)},
        .ikmR = {a14_ikmR, sizeof(a14_ikmR)},
        .ikmS = &ikmS_datum,
        .info = {info, sizeof(info)},
        .psk = &psk_datum,
        .psk_id = &psk_id_datum,
        .expected_enc = {a14_expected_enc, sizeof(a14_expected_enc)},
        .encryption_parameters = enc_params,
        .num_encryption_parameters = sizeof(enc_params) / sizeof(enc_params[0]),
        .exporter_parameters = exporter_params,
        .num_exporter_parameters =
            sizeof(exporter_params) / sizeof(exporter_params[0])};

    test_hpke(ctx, &params);
}

void run_all_benchmarks(benchmarker_context *ctx)
{
    for (int i = 0; i < benchmarker_get_number_of_rounds(); i++)
    {
        benchmarker_set_current_mode(ctx, BENCHMARKER_TARGET_HPKE_MODE_BASE);
        rfc9180_a11(ctx);
        benchmarker_set_current_mode(ctx, BENCHMARKER_TARGET_HPKE_MODE_PSK);
        rfc9180_a12(ctx);
        benchmarker_set_current_mode(ctx, BENCHMARKER_TARGET_HPKE_MODE_AUTH);
        rfc9180_a13(ctx);
        benchmarker_set_current_mode(ctx, BENCHMARKER_TARGET_HPKE_MODE_PSKAUTH);
        rfc9180_a14(ctx);
        benchmarker_round_done(ctx);
    }
}
