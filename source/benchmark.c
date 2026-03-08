#include "benchmark.h"
#include "constants.h"
#include "utils.h"

#include <string.h>

#include <openssl/hpke.h>

#define NUM_BENCHMARKS 4

typedef void (*benchmark_func_t)(const keys *, size_t);

#define GNUTLS_BENCHMARK_ENTRY 0
#define OPENSSL_BENCHMARK_ENTRY 1

#define ENCAP_AND_SEAL_BENCHMARK_ENTRY 0
#define DECAP_AND_OPEN_BENCHMARK_ENTRY 1

#define NUMBER_OF_IMPLEMENTATIONS 2
#define NUMBER_OF_OPERATIONS 2

static struct benchmarks_report
{
    double encap_time_ms[NUMBER_OF_IMPLEMENTATIONS][NUMBER_OF_OPERATIONS];
    double seal_time_ms[NUMBER_OF_IMPLEMENTATIONS][NUMBER_OF_OPERATIONS];
    double decap_time_ms[NUMBER_OF_IMPLEMENTATIONS][NUMBER_OF_OPERATIONS];
    double open_time_ms[NUMBER_OF_IMPLEMENTATIONS][NUMBER_OF_OPERATIONS];

    int num_benchmarks_run;
} benchmark_report;

static void shuffle_benchmarks(benchmark_func_t *benches, size_t num_benches)
{
    for (size_t i = num_benches - 1; i > 0; i--)
    {
        size_t j = rand() % (i + 1);
        benchmark_func_t temp = benches[i];
        benches[i] = benches[j];
        benches[j] = temp;
    }
}

static void bench_openssl_sender_base(const keys *keys, size_t iterations)
{
    int ret = 0;
    unsigned char exp[32];
    size_t explen = sizeof(exp);
    double total_encap_time = 0, total_seal_time = 0;

    for (size_t i = 0; i < iterations; i++)
    {
        unsigned char *enc = NULL;
        size_t enclen = 0;
        unsigned char *ct = NULL;
        size_t ctlen = 0;
        double encap_time_ms = 0, seal_time_ms = 0;

        ret = openssl_hpke_encap_and_seal_benchmark(
            OSSL_HPKE_MODE_BASE, keys->ossl_recipient_keypair.public_key_raw,
            keys->ossl_recipient_keypair.public_key_raw_len, NULL,
            OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, NULL, 0, NULL, info,
            sizeof(info) - 1, aad, sizeof(aad) - 1, pt, sizeof(pt) - 1, &enc,
            &enclen, &ct, &ctlen, exp, explen, &encap_time_ms, &seal_time_ms);

        total_encap_time += encap_time_ms;
        total_seal_time += seal_time_ms;

        OPENSSL_free(enc);
        OPENSSL_free(ct);

        if (ret != 1)
        {
            fprintf(stderr, "OpenSSL HPKE encap+seal failed at iteration %zu\n",
                    i);
            return;
        }
    }

    benchmark_report.encap_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                  [ENCAP_AND_SEAL_BENCHMARK_ENTRY] =
        total_encap_time / iterations;
    benchmark_report
        .seal_time_ms[OPENSSL_BENCHMARK_ENTRY][ENCAP_AND_SEAL_BENCHMARK_ENTRY] =
        total_seal_time / iterations;

    // PRINT_BENCHMARK_RESULT();
    // benchmark_report
    //     .time_ms[OPENSSL_BENCHMARK_ENTRY][ENCAP_AND_SEAL_BENCHMARK_ENTRY] =
    //     (end - start) / iterations;
}

void bench_gnutls_sender_base(const keys *keys, size_t iterations)
{
    int ret = 0;
    double total_encap_time = 0, total_seal_time = 0;

    gnutls_datum_t info_d = {.data = (unsigned char *)info,
                             .size = (unsigned int)(sizeof(info) - 1)};

    for (size_t i = 0; i < iterations; i++)
    {
        double encap_time_ms = 0, seal_time_ms = 0;
        gnutls_datum_t enc = {0};
        gnutls_datum_t cipher_text = {0};

        gnutls_datum_t plain_text = {.data = (unsigned char *)pt,
                                     .size = sizeof(pt) - 1};

        ret = gnutls_hpke_encap_and_seal_benchmark(
            GNUTLS_HPKE_MODE_BASE, keys->gnutls_recipient_keypair.public_key,
            NULL, GNUTLS_HPKE_KEM_DHKEM_X25519, GNUTLS_HPKE_KDF_HKDF_SHA256,
            GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, NULL, NULL, &info_d, aad,
            sizeof(aad) - 1, &plain_text, &enc, &cipher_text, &encap_time_ms,
            &seal_time_ms);
        if (ret != 0)
        {
            fprintf(stderr, "GnuTLS encap+seal failed at iteration %zu\n", i);
            return;
        }

        total_encap_time += encap_time_ms;
        total_seal_time += seal_time_ms;

        gnutls_free(enc.data);
        gnutls_free(cipher_text.data);
    }

    benchmark_report
        .encap_time_ms[GNUTLS_BENCHMARK_ENTRY][ENCAP_AND_SEAL_BENCHMARK_ENTRY] =
        total_encap_time / iterations;
    benchmark_report
        .seal_time_ms[GNUTLS_BENCHMARK_ENTRY][ENCAP_AND_SEAL_BENCHMARK_ENTRY] =
        total_seal_time / iterations;

    // PRINT_BENCHMARK_RESULT();
    // benchmark_report
    //     .time_ms[GNUTLS_BENCHMARK_ENTRY][ENCAP_AND_SEAL_BENCHMARK_ENTRY] =
    //     (end - start) / iterations;
}

void bench_openssl_recipient_base(const keys *keys, size_t iterations)
{
    // PRINT_BENCHMARK_RUN();
    int ret = 0;
    double total_decap_time = 0, total_open_time = 0;

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

    for (size_t i = 0; i < iterations; i++)
    {
        unsigned char pt_out[256];
        size_t pt_out_len = sizeof(pt_out);
        double decap_time_ms = 0, open_time_ms = 0;

        ret = openssl_hpke_decap_and_open_benchmark(
            OSSL_HPKE_MODE_BASE, keys->ossl_recipient_keypair.pkey, NULL, 0,
            OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, NULL, 0, NULL, info,
            sizeof(info) - 1, aad, sizeof(aad) - 1, enc, enclen, ct, ctlen,
            pt_out, &pt_out_len, &decap_time_ms, &open_time_ms);
        if (ret != 1)
        {
            fprintf(stderr, "OpenSSL HPKE decap+open failed at iteration %zu\n",
                    i);
            return;
        }

        total_decap_time += decap_time_ms;
        total_open_time += open_time_ms;
    }

    benchmark_report.decap_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                  [DECAP_AND_OPEN_BENCHMARK_ENTRY] =
        total_decap_time / iterations;
    benchmark_report
        .open_time_ms[OPENSSL_BENCHMARK_ENTRY][DECAP_AND_OPEN_BENCHMARK_ENTRY] =
        total_open_time / iterations;

    // PRINT_BENCHMARK_RESULT();
    // benchmark_report
    //     .time_ms[OPENSSL_BENCHMARK_ENTRY][DECAP_AND_OPEN_BENCHMARK_ENTRY] =
    //     (end - start) / iterations;
}

void bench_gnutls_recipient_base(const keys *keys, size_t iterations)
{
    // PRINT_BENCHMARK_RUN();
    int ret = 0;
    double total_decap_time = 0, total_open_time = 0;

    gnutls_datum_t info_d = {.data = (unsigned char *)info,
                             .size = (unsigned int)(sizeof(info) - 1)};

    gnutls_datum_t enc;
    gnutls_datum_t ct;

    gnutls_datum_t plain_text = {.data = (unsigned char *)pt,
                                 .size = sizeof(pt) - 1};

    ret = gnutls_hpke_encap_and_seal(
        GNUTLS_HPKE_MODE_BASE, keys->gnutls_recipient_keypair.public_key, NULL,
        GNUTLS_HPKE_KEM_DHKEM_X25519, GNUTLS_HPKE_KDF_HKDF_SHA256,
        GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, NULL, NULL, &info_d, aad,
        sizeof(aad) - 1, &enc, &plain_text, &ct);
    if (ret != 0)
    {
        fprintf(stderr, "GnuTLS decap+open failed\n");
        return;
    }

    for (size_t i = 0; i < iterations; i++)
    {
        double decap_time_ms = 0, open_time_ms = 0;
        gnutls_datum_t plaintext = {0};
        plaintext.size = 256;
        plaintext.data = gnutls_malloc(plaintext.size);

        ret = gnutls_hpke_decap_and_open_benchmark(
            GNUTLS_HPKE_MODE_BASE, keys->gnutls_recipient_keypair.private_key,
            NULL, GNUTLS_HPKE_KEM_DHKEM_X25519, GNUTLS_HPKE_KDF_HKDF_SHA256,
            GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, NULL, NULL, &info_d, aad,
            sizeof(aad) - 1, &enc, &ct, &plaintext, &decap_time_ms,
            &open_time_ms);
        if (ret != 0)
        {
            fprintf(stderr, "GnuTLS decap+open failed at iteration %zu\n", i);
            return;
        }

        total_decap_time += decap_time_ms;
        total_open_time += open_time_ms;

        gnutls_free(plaintext.data);
    }

    benchmark_report
        .decap_time_ms[GNUTLS_BENCHMARK_ENTRY][DECAP_AND_OPEN_BENCHMARK_ENTRY] =
        total_decap_time / iterations;
    benchmark_report
        .open_time_ms[GNUTLS_BENCHMARK_ENTRY][DECAP_AND_OPEN_BENCHMARK_ENTRY] =
        total_open_time / iterations;

    // PRINT_BENCHMARK_RESULT();
    // benchmark_report
    //     .time_ms[GNUTLS_BENCHMARK_ENTRY][DECAP_AND_OPEN_BENCHMARK_ENTRY] =
    //     (end - start) / iterations;
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
    printf("\n=============================== BENCHMARKS "
           "=============================\n");

    printf("%-15s | %-15s | %-15s | %-16s |\n", "", "OpenSSL", "GnuTLS",
           "OpenSSL/GnuTLS");
    printf("----------------+-----------------+----------------"
           "-+------------------+\n");
    printf("%-15s | %-13.2fus | %-13.2fus | %-15.2fx |\n", "Encapsulation",
           benchmark_report.encap_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                         [ENCAP_AND_SEAL_BENCHMARK_ENTRY],
           benchmark_report.encap_time_ms[GNUTLS_BENCHMARK_ENTRY]
                                         [ENCAP_AND_SEAL_BENCHMARK_ENTRY],
           benchmark_report.encap_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                         [ENCAP_AND_SEAL_BENCHMARK_ENTRY] /
               benchmark_report.encap_time_ms[GNUTLS_BENCHMARK_ENTRY]
                                             [ENCAP_AND_SEAL_BENCHMARK_ENTRY]);
    printf("%-15s | %-13.2fus | %-13.2fus | %-15.2fx |\n", "Seal",
           benchmark_report.seal_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                        [ENCAP_AND_SEAL_BENCHMARK_ENTRY],
           benchmark_report.seal_time_ms[GNUTLS_BENCHMARK_ENTRY]
                                        [ENCAP_AND_SEAL_BENCHMARK_ENTRY],
           benchmark_report.seal_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                        [ENCAP_AND_SEAL_BENCHMARK_ENTRY] /
               benchmark_report.seal_time_ms[GNUTLS_BENCHMARK_ENTRY]
                                            [ENCAP_AND_SEAL_BENCHMARK_ENTRY]);
    printf("%-15s | %-13.2fus | %-13.2fus | %-15.2fx |\n", "Decapsulation",
           benchmark_report.decap_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                         [DECAP_AND_OPEN_BENCHMARK_ENTRY],
           benchmark_report.decap_time_ms[GNUTLS_BENCHMARK_ENTRY]
                                         [DECAP_AND_OPEN_BENCHMARK_ENTRY],
           benchmark_report.decap_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                         [DECAP_AND_OPEN_BENCHMARK_ENTRY] /
               benchmark_report.decap_time_ms[GNUTLS_BENCHMARK_ENTRY]
                                             [DECAP_AND_OPEN_BENCHMARK_ENTRY]);
    printf("%-15s | %-13.2fus | %-13.2fus | %-15.2fx |\n", "Open",
           benchmark_report.open_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                        [DECAP_AND_OPEN_BENCHMARK_ENTRY],
           benchmark_report.open_time_ms[GNUTLS_BENCHMARK_ENTRY]
                                        [DECAP_AND_OPEN_BENCHMARK_ENTRY],
           benchmark_report.open_time_ms[OPENSSL_BENCHMARK_ENTRY]
                                        [DECAP_AND_OPEN_BENCHMARK_ENTRY] /
               benchmark_report.open_time_ms[GNUTLS_BENCHMARK_ENTRY]
                                            [DECAP_AND_OPEN_BENCHMARK_ENTRY]);

    printf("==================================================================="
           "=====\n");
}
