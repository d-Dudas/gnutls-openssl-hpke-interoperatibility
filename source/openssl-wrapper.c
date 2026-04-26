#include "openssl-wrapper.h"
#include "benchmarker.h"
#include "constants.h"

#include <openssl/evp.h>
#include <openssl/hpke.h>

#include <stdio.h>
#include <string.h>

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

#define OSSL_HPKE_TSTSIZE 512

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

static OSSL_LIB_CTX *testctx = NULL;
static char *testpropq = "provider=default";

typedef struct
{
    int mode;
    OSSL_HPKE_SUITE suite;
    const unsigned char *ikmE;
    size_t ikmElen;
    const unsigned char *ikmR;
    size_t ikmRlen;
    const unsigned char *expected_secret;
    size_t expected_secretlen;
    const unsigned char *ksinfo;
    size_t ksinfolen;
    const unsigned char *ikmAuth;
    size_t ikmAuthlen;
    const unsigned char *psk;
    size_t psklen;
    const char *pskid; /* want terminating NUL here */
} TEST_BASEDATA;

typedef struct
{
    int seq;
    const unsigned char *pt;
    size_t ptlen;
    const unsigned char *aad;
    size_t aadlen;
    const unsigned char *expected_ct;
    size_t expected_ctlen;
} TEST_AEADDATA;

typedef struct
{
    const unsigned char *context;
    size_t contextlen;
    const unsigned char *expected_secret;
    size_t expected_secretlen;
} TEST_EXPORTDATA;

static int test_true(int x)
{
    if (x == 0)
    {
        fprintf(stderr, "Test failure at %s:%d\n", __FILE__, __LINE__);
        return 0;
    }
    return 1;
}

#define TEST_true(x) test_true(x)

#define TEST_ptr(x) test_true((x) != NULL)

#define TEST_false(x) test_true((x) == 0)

static int do_testhpke(benchmarker_context *ctx, const TEST_BASEDATA *base,
                       const TEST_AEADDATA *aead, size_t aeadsz,
                       const TEST_EXPORTDATA *export, size_t exportsz)
{
    OSSL_LIB_CTX *libctx = testctx;
    const char *propq = testpropq;
    OSSL_HPKE_CTX *sealctx = NULL, *openctx = NULL;
    unsigned char ct[256];
    unsigned char enc[256];
    unsigned char ptout[256];
    size_t ptoutlen = sizeof(ptout);
    size_t enclen = sizeof(enc);
    size_t ctlen = sizeof(ct);
    unsigned char pub[OSSL_HPKE_TSTSIZE];
    size_t publen = sizeof(pub);
    EVP_PKEY *privE = NULL;
    unsigned char authpub[OSSL_HPKE_TSTSIZE];
    size_t authpublen = sizeof(authpub);
    EVP_PKEY *authpriv = NULL;
    unsigned char rpub[OSSL_HPKE_TSTSIZE];
    size_t rpublen = sizeof(pub);
    EVP_PKEY *privR = NULL;
    int ret = 0;
    size_t i;
    uint64_t lastseq = 0;
    double starttime, endtime;

    starttime = benchmarker_get_now();
    ret = OSSL_HPKE_keygen(base->suite, pub, &publen, &privE, base->ikmE,
                           base->ikmElen, libctx, propq);
    endtime = benchmarker_get_now();
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_OPENSSL,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_KEYGEN, starttime,
                           endtime);
    if (ret == 0)
    {
        goto end;
    }

    sealctx = OSSL_HPKE_CTX_new(base->mode, base->suite, OSSL_HPKE_ROLE_SENDER,
                                libctx, propq);
    if (sealctx == NULL)
    {
        goto end;
    }

    ret = OSSL_HPKE_CTX_set1_ikme(sealctx, base->ikmE, base->ikmElen);
    if (ret == 0)
    {
        goto end;
    }

    if (base->mode == OSSL_HPKE_MODE_AUTH ||
        base->mode == OSSL_HPKE_MODE_PSKAUTH)
    {
        ret = (base->ikmAuth != NULL && base->ikmAuthlen > 0);
        if (ret == 0)
        {
            goto end;
        }

        if (!TEST_true(OSSL_HPKE_keygen(base->suite, authpub, &authpublen,
                                        &authpriv, base->ikmAuth,
                                        base->ikmAuthlen, libctx, propq)))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_set1_authpriv(sealctx, authpriv)))
            goto end;
    }
    if (!TEST_true(OSSL_HPKE_keygen(base->suite, rpub, &rpublen, &privR,
                                    base->ikmR, base->ikmRlen, libctx, propq)))
        goto end;

    if (base->mode == OSSL_HPKE_MODE_PSK ||
        base->mode == OSSL_HPKE_MODE_PSKAUTH)
    {
        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(sealctx, base->pskid, base->psk,
                                              base->psklen)))
            goto end;
    }
    starttime = benchmarker_get_now();
    if (!TEST_true(OSSL_HPKE_encap(sealctx, enc, &enclen, rpub, rpublen,
                                   base->ksinfo, base->ksinfolen)))
        goto end;
    endtime = benchmarker_get_now();
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_OPENSSL,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_ENCAPS, starttime,
                           endtime);
    double duration_total = 0;
    for (i = 0; i < aeadsz; ++i)
    {
        ctlen = sizeof(ct);
        memset(ct, 0, ctlen);
        starttime = benchmarker_get_now();
        double s = now_ms();
        if (!TEST_true(OSSL_HPKE_seal(sealctx, ct, &ctlen, aead[i].aad,
                                      aead[i].aadlen, aead[i].pt,
                                      aead[i].ptlen)))
            goto end;
        double e = now_ms();
        printf("openssl,seal,,%.5f\n", e - s);
        endtime = benchmarker_get_now();
        duration_total += (endtime - starttime);
        if (!TEST_true(OSSL_HPKE_CTX_get_seq(sealctx, &lastseq)))
            goto end;
        if (lastseq != (uint64_t)(i + 1))
            goto end;
    }
    duration_total /= aeadsz;
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_OPENSSL,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_SEAL, 0,
                           duration_total);
    if (!TEST_ptr(openctx = OSSL_HPKE_CTX_new(base->mode, base->suite,
                                              OSSL_HPKE_ROLE_RECEIVER, libctx,
                                              propq)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_PSK ||
        base->mode == OSSL_HPKE_MODE_PSKAUTH)
    {
        if (!TEST_true(base->pskid != NULL && base->psk != NULL &&
                       base->psklen > 0))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(openctx, base->pskid, base->psk,
                                              base->psklen)))
            goto end;
    }
    if (base->mode == OSSL_HPKE_MODE_AUTH ||
        base->mode == OSSL_HPKE_MODE_PSKAUTH)
    {
        if (!TEST_true(
                OSSL_HPKE_CTX_set1_authpub(openctx, authpub, authpublen)))
            goto end;
    }
    starttime = benchmarker_get_now();
    if (!TEST_true(OSSL_HPKE_decap(openctx, enc, enclen, privR, base->ksinfo,
                                   base->ksinfolen)))
        goto end;
    endtime = benchmarker_get_now();
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_OPENSSL,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_DECAPS, starttime,
                           endtime);
    duration_total = 0;
    for (i = 0; i < aeadsz; ++i)
    {
        ptoutlen = sizeof(ptout);
        memset(ptout, 0, ptoutlen);
        starttime = benchmarker_get_now();
        if (!TEST_true(OSSL_HPKE_open(openctx, ptout, &ptoutlen, aead[i].aad,
                                      aead[i].aadlen, aead[i].expected_ct,
                                      aead[i].expected_ctlen)))
            goto end;
        endtime = benchmarker_get_now();
        duration_total += endtime - starttime;
        /* check the sequence is being incremented as expected */
        if (!TEST_true(OSSL_HPKE_CTX_get_seq(openctx, &lastseq)))
            goto end;
        if (lastseq != (uint64_t)(i + 1))
            goto end;
    }
    benchmarker_set_result(ctx, BENCHMARKER_TARGET_LIBRARY_OPENSSL,
                           BENCHMARKER_TARGET_HPKE_PROCEDURE_OPEN, 0,
                           duration_total);
    /* check exporters */
    for (i = 0; i < exportsz; ++i)
    {
        size_t len = export[i].expected_secretlen;
        unsigned char eval[OSSL_HPKE_TSTSIZE];

        if (len > sizeof(eval))
            goto end;
        /* export with too long label should fail */
        if (!TEST_false(
                OSSL_HPKE_export(sealctx, eval, len, export[i].context, -1)))
            goto end;
        /* good export call */
        if (!TEST_true(OSSL_HPKE_export(sealctx, eval, len, export[i].context,
                                        export[i].contextlen)))
            goto end;

        /* check seal fails if export only mode */
        if (aeadsz == 0)
        {

            if (!TEST_false(OSSL_HPKE_seal(sealctx, ct, &ctlen, NULL, 0, ptout,
                                           ptoutlen)))
                goto end;
        }
    }
    ret = 1;
end:
    OSSL_HPKE_CTX_free(sealctx);
    OSSL_HPKE_CTX_free(openctx);
    EVP_PKEY_free(privE);
    EVP_PKEY_free(privR);
    EVP_PKEY_free(authpriv);
    return ret;
}

static int rfc9180_a11(benchmarker_context *ctx)
{
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_BASE,
        {OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
         OSSL_HPKE_AEAD_ID_AES_GCM_128},
        a11_ikmE,
        sizeof(a11_ikmE),
        a11_ikmR,
        sizeof(a11_ikmR),
        a11_expected_enc,
        sizeof(a11_expected_enc),
        info,
        sizeof(info),
        NULL,
        0, /* no auth ikm */
        NULL,
        0,
        NULL /* no psk */
    };
    const TEST_AEADDATA aeaddata[] = {
        {0, plaintext, sizeof(plaintext), seq0_aad, sizeof(seq0_aad),
         a11_seq0_expected_ct, sizeof(a11_seq0_expected_ct)},
        {1, plaintext, sizeof(plaintext), seq1_aad, sizeof(seq1_aad),
         a11_seq1_expected_ct, sizeof(a11_seq1_expected_ct)},
    };

    const TEST_EXPORTDATA exportdata[] = {
        {NULL, 0, a11_expected_exporter_value_1,
         sizeof(a11_expected_exporter_value_1)},
        {exporter_context_2, sizeof(exporter_context_2),
         a11_expected_exporter_value_2, sizeof(a11_expected_exporter_value_2)},
        {exporter_context_3, sizeof(exporter_context_3),
         a11_expected_exporter_value_3, sizeof(a11_expected_exporter_value_3)},
    };
    return do_testhpke(ctx, &basedata, aeaddata, OSSL_NELEM(aeaddata),
                       exportdata, OSSL_NELEM(exportdata));
}

static int rfc9180_a12(benchmarker_context *ctx)
{
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_PSK,
        {OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
         OSSL_HPKE_AEAD_ID_AES_GCM_128},
        a12_ikmE,
        sizeof(a12_ikmE),
        a12_ikmR,
        sizeof(a12_ikmR),
        a12_expected_enc,
        sizeof(a12_expected_enc),
        info,
        sizeof(info),
        NULL,
        0, /* no auth ikm */
        psk,
        sizeof(psk),
        (char *)psk_id,
    };
    const TEST_AEADDATA aeaddata[] = {
        {0, plaintext, sizeof(plaintext), seq0_aad, sizeof(seq0_aad),
         a12_seq0_expected_ct, sizeof(a12_seq0_expected_ct)},
        {1, plaintext, sizeof(plaintext), seq1_aad, sizeof(seq1_aad),
         a12_seq1_expected_ct, sizeof(a12_seq1_expected_ct)},
    };

    const TEST_EXPORTDATA exportdata[] = {
        {NULL, 0, a12_expected_exporter_value_1,
         sizeof(a12_expected_exporter_value_1)},
        {exporter_context_2, sizeof(exporter_context_2),
         a12_expected_exporter_value_2, sizeof(a12_expected_exporter_value_2)},
        {exporter_context_3, sizeof(exporter_context_3),
         a12_expected_exporter_value_3, sizeof(a12_expected_exporter_value_3)},
    };
    return do_testhpke(ctx, &basedata, aeaddata, OSSL_NELEM(aeaddata),
                       exportdata, OSSL_NELEM(exportdata));
}

static int rfc9180_a13(benchmarker_context *ctx)
{
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_AUTH,
        {OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
         OSSL_HPKE_AEAD_ID_AES_GCM_128},
        a13_ikmE,
        sizeof(a13_ikmE),
        a13_ikmR,
        sizeof(a13_ikmR),
        a13_expected_enc,
        sizeof(a13_expected_enc),
        info,
        sizeof(info),
        a13_ikmS,
        sizeof(a13_ikmS),
        NULL,
        0,   /* no psk */
        NULL /* no psk id */
    };
    const TEST_AEADDATA aeaddata[] = {
        {0, plaintext, sizeof(plaintext), seq0_aad, sizeof(seq0_aad),
         a13_seq0_expected_ct, sizeof(a13_seq0_expected_ct)},
        {1, plaintext, sizeof(plaintext), seq1_aad, sizeof(seq1_aad),
         a13_seq1_expected_ct, sizeof(a13_seq1_expected_ct)},
    };

    const TEST_EXPORTDATA exportdata[] = {
        {NULL, 0, a13_expected_exporter_value_1,
         sizeof(a13_expected_exporter_value_1)},
        {exporter_context_2, sizeof(exporter_context_2),
         a13_expected_exporter_value_2, sizeof(a13_expected_exporter_value_2)},
        {exporter_context_3, sizeof(exporter_context_3),
         a13_expected_exporter_value_3, sizeof(a13_expected_exporter_value_3)},
    };
    return do_testhpke(ctx, &basedata, aeaddata, OSSL_NELEM(aeaddata),
                       exportdata, OSSL_NELEM(exportdata));
}

static int rfc9180_a14(benchmarker_context *ctx)
{
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_PSKAUTH,
        {OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
         OSSL_HPKE_AEAD_ID_AES_GCM_128},
        a14_ikmE,
        sizeof(a14_ikmE),
        a14_ikmR,
        sizeof(a14_ikmR),
        a14_expected_enc,
        sizeof(a14_expected_enc),
        info,
        sizeof(info),
        a14_ikmS,
        sizeof(a14_ikmS),
        psk,
        sizeof(psk),
        (char *)psk_id,
    };
    const TEST_AEADDATA aeaddata[] = {
        {0, plaintext, sizeof(plaintext), seq0_aad, sizeof(seq0_aad),
         a14_seq0_expected_ct, sizeof(a14_seq0_expected_ct)},
        {1, plaintext, sizeof(plaintext), seq1_aad, sizeof(seq1_aad),
         a14_seq1_expected_ct, sizeof(a14_seq1_expected_ct)},
    };

    const TEST_EXPORTDATA exportdata[] = {
        {NULL, 0, a14_expected_exporter_value1,
         sizeof(a14_expected_exporter_value1)},
        {exporter_context_2, sizeof(exporter_context_2),
         a14_expected_exporter_value2, sizeof(a14_expected_exporter_value2)},
        {exporter_context_3, sizeof(exporter_context_3),
         a14_expected_exporter_value3, sizeof(a14_expected_exporter_value3)},
    };
    return do_testhpke(ctx, &basedata, aeaddata, OSSL_NELEM(aeaddata),
                       exportdata, OSSL_NELEM(exportdata));
}

void run_a11_benchmark(benchmarker_context *ctx)
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
