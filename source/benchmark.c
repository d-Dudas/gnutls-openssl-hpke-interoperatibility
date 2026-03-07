#include "benchmark.h"
#include "constants.h"
#include "utils.h"

#include <string.h>

#include <openssl/hpke.h>

#define PRINT_BENCHMARK_RUN()                                                  \
    {                                                                          \
        printf("[--RUN--] %s\n", __func__);                                    \
        benchmark_report.num_benchmarks_run++;                                 \
        strncpy(benchmark_report                                               \
                    .benchmark_name[benchmark_report.num_benchmarks_run - 1],  \
                __func__, 255);                                                \
    }

#define PRINT_BENCHMARK_RESULT()                                               \
    {                                                                          \
        printf("[--RESULT--] %s: %.2f ms\n", __func__,                         \
               (end - start) / iterations);                                    \
        benchmark_report.time_ms[benchmark_report.num_benchmarks_run - 1] =    \
            (end - start) / iterations;                                        \
    }

#define NUM_BENCHMARKS 4

typedef void (*benchmark_func_t)(const keys *, size_t);

static struct benchmarks_report
{
    char benchmark_name[NUM_BENCHMARKS][256];
    double time_ms[NUM_BENCHMARKS];

    int num_benchmarks_run;
} benchmark_report;

static void shuffle_benchmarks(benchmark_func_t *benches, size_t num_benches)
{
    for (size_t i = num_benches - 1; i > 0; i--)
    {
        fprintf(stdout, "Shuffling benchmark %zu/%zu\n", num_benches - i,
                num_benches);
        size_t j = rand() % (i + 1);
        benchmark_func_t temp = benches[i];
        benches[i] = benches[j];
        benches[j] = temp;
    }
}

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000000.0 + (double)ts.tv_nsec;
}

static void bench_openssl_sender_base(const keys *keys, size_t iterations)
{
    PRINT_BENCHMARK_RUN();
    int ret = 0;
    double start, end;
    unsigned char exp[32];
    size_t explen = sizeof(exp);

    start = now_ns();

    for (size_t i = 0; i < iterations; i++)
    {
        unsigned char *enc = NULL;
        size_t enclen = 0;
        unsigned char *ct = NULL;
        size_t ctlen = 0;

        ret = openssl_hpke_encap_and_seal(
            OSSL_HPKE_MODE_BASE, keys->ossl_recipient_keypair.public_key_raw,
            keys->ossl_recipient_keypair.public_key_raw_len, NULL,
            OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, NULL, 0, NULL, info,
            sizeof(info) - 1, aad, sizeof(aad) - 1, pt, sizeof(pt) - 1, &enc,
            &enclen, &ct, &ctlen, exp, explen);

        OPENSSL_free(enc);
        OPENSSL_free(ct);

        if (ret != 1)
        {
            fprintf(stderr, "OpenSSL HPKE encap+seal failed at iteration %zu\n",
                    i);
            return;
        }
    }

    end = now_ns();

    PRINT_BENCHMARK_RESULT();
}

void bench_gnutls_sender_base(const keys *keys, size_t iterations)
{
    PRINT_BENCHMARK_RUN();
    int ret = 0;
    double start, end;

    gnutls_datum_t info_d = {.data = (unsigned char *)info,
                             .size = (unsigned int)(sizeof(info) - 1)};

    start = now_ns();

    for (size_t i = 0; i < iterations; i++)
    {
        gnutls_datum_t enc = {0};
        gnutls_datum_t cipher_text = {0};

        gnutls_datum_t plain_text = {.data = (unsigned char *)pt,
                                     .size = sizeof(pt) - 1};

        ret = gnutls_hpke_encap_and_seal(
            keys->gnutls_recipient_keypair.public_key, NULL,
            GNUTLS_HPKE_KEM_DHKEM_X25519, GNUTLS_HPKE_KDF_HKDF_SHA256,
            GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, NULL, NULL, &info_d, aad,
            sizeof(aad) - 1, &plain_text, &enc, &cipher_text);
        if (ret != 0)
        {
            fprintf(stderr, "GnuTLS encap+seal failed at iteration %zu\n", i);
            return;
        }

        gnutls_free(enc.data);
        gnutls_free(cipher_text.data);
    }

    end = now_ns();

    PRINT_BENCHMARK_RESULT();
}

void bench_openssl_recipient_base(const keys *keys, size_t iterations)
{
    PRINT_BENCHMARK_RUN();
    int ret = 0;
    double start, end;

    unsigned char *enc;
    size_t enclen;
    unsigned char *ct;
    size_t ctlen;
    unsigned char exp[32];
    size_t explen = sizeof(exp);

    ret = openssl_hpke_encap_and_seal(
        OSSL_HPKE_MODE_BASE, keys->ossl_recipient_keypair.public_key_raw,
        keys->ossl_recipient_keypair.public_key_raw_len, NULL,
        OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
        OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, NULL, 0, NULL, info,
        sizeof(info) - 1, aad, sizeof(aad) - 1, pt, sizeof(pt) - 1, &enc,
        &enclen, &ct, &ctlen, exp, explen);
    if (ret != 1)
    {
        fprintf(stderr, "OpenSSL HPKE encap+seal failed\n");
        return;
    }

    start = now_ns();

    for (size_t i = 0; i < iterations; i++)
    {
        unsigned char pt_out[256];
        size_t pt_out_len = sizeof(pt_out);

        ret = openssl_hpke_decap_and_open(
            OSSL_HPKE_MODE_BASE, keys->ossl_recipient_keypair.pkey, NULL, 0,
            OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, NULL, 0, NULL, info,
            sizeof(info) - 1, aad, sizeof(aad) - 1, enc, enclen, ct, ctlen,
            pt_out, &pt_out_len);
        if (ret != 1)
        {
            fprintf(stderr, "OpenSSL HPKE decap+open failed at iteration %zu\n",
                    i);
            return;
        }
    }

    end = now_ns();

    PRINT_BENCHMARK_RESULT();
}

void bench_gnutls_recipient_base(const keys *keys, size_t iterations)
{
    PRINT_BENCHMARK_RUN();
    int ret = 0;
    double start, end;

    gnutls_datum_t info_d = {.data = (unsigned char *)info,
                             .size = (unsigned int)(sizeof(info) - 1)};

    gnutls_datum_t enc;
    gnutls_datum_t ct;

    gnutls_datum_t plain_text = {.data = (unsigned char *)pt,
                                 .size = sizeof(pt) - 1};

    ret = gnutls_hpke_encap_and_seal(
        keys->gnutls_recipient_keypair.public_key, NULL,
        GNUTLS_HPKE_KEM_DHKEM_X25519, GNUTLS_HPKE_KDF_HKDF_SHA256,
        GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, NULL, NULL, &info_d, aad,
        sizeof(aad) - 1, &enc, &plain_text, &ct);
    if (ret != 0)
    {
        fprintf(stderr, "GnuTLS encap+seal failed\n");
        return;
    }

    start = now_ns();

    for (size_t i = 0; i < iterations; i++)
    {
        unsigned char pt_out[256];
        size_t pt_out_len = sizeof(pt_out);

        ret = gnutls_hpke_decap_and_open(
            keys->gnutls_recipient_keypair.private_key, NULL,
            GNUTLS_HPKE_KEM_DHKEM_X25519, GNUTLS_HPKE_KDF_HKDF_SHA256,
            GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, NULL, NULL, &info_d, aad,
            sizeof(aad) - 1, &enc, &ct, pt_out, &pt_out_len);
        if (ret != 0)
        {
            fprintf(stderr, "GnuTLS decap+open failed at iteration %zu\n", i);
            return;
        }
    }

    end = now_ns();

    PRINT_BENCHMARK_RESULT();
}

void run_all_benchmarks()
{
    int ret;
    keys keys;

    ret = gnutls_global_init();
    if (ret != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "gnutls_global_init failed\n");
        goto cleanup;
    }

    ret = generate_keypair(&keys.ossl_sender_keypair,
                           &keys.gnutls_sender_keypair);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to generate sender keypair\n");
        goto cleanup;
    }

    ret = generate_keypair(&keys.ossl_recipient_keypair,
                           &keys.gnutls_recipient_keypair);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to generate recipient keypair\n");
        goto cleanup;
    }

    srand((unsigned int)time(NULL));

    benchmark_func_t benchmarks[] = {
        bench_openssl_sender_base, bench_openssl_recipient_base,
        bench_gnutls_recipient_base, bench_gnutls_sender_base};

    shuffle_benchmarks(benchmarks, NUM_BENCHMARKS);

    const size_t iterations = 1000;
    fprintf(stdout, "\nRunning %d benchmarks with %zu iterations each...\n",
            NUM_BENCHMARKS, iterations);
    for (size_t i = 0; i < NUM_BENCHMARKS; i++)
    {
        benchmarks[i](&keys, iterations);
    }

cleanup:
    gnutls_kp_deinit(&keys.gnutls_sender_keypair);
    gnutls_kp_deinit(&keys.gnutls_recipient_keypair);
    openssl_kp_deinit(&keys.ossl_sender_keypair);
    openssl_kp_deinit(&keys.ossl_recipient_keypair);

    gnutls_global_deinit();
}

void print_benchmarks_report()
{
    printf("\n==================== BENCHMARKS ===================\n");
    for (int i = 0; i < benchmark_report.num_benchmarks_run; i++)
    {
        printf("%s: \t%.2f ms\n", benchmark_report.benchmark_name[i],
               benchmark_report.time_ms[i]);
    }
    printf("================================================\n");
}
