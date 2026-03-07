#include "tests.h"
#include "constants.h"
#include "gnutls_wrapper.h"
#include "openssl_wrapper.h"
#include "utils.h"

#include <openssl/hpke.h>

#include <string.h>

#define PRINT_TEST_RUN()                                                       \
    {                                                                          \
        printf("[--RUN--] %s\n", __func__);                                    \
        final_report.num_tests_run++;                                          \
        strncpy(final_report.test_name[final_report.num_tests_run - 1],        \
                __func__, 255);                                                \
    }

#define PRINT_TEST_PASS()                                                      \
    {                                                                          \
        printf("[--PASS--] %s\n", __func__);                                   \
        strncpy(final_report.test_result[final_report.num_tests_run - 1],      \
                "PASS", 15);                                                   \
    }

#define PRINT_TEST_FAIL()                                                      \
    {                                                                          \
        printf("[--FAIL--] %s\n", __func__);                                   \
        strncpy(final_report.test_result[final_report.num_tests_run - 1],      \
                "FAIL", 15);                                                   \
    }

#define WITHOUT_SENDER_PRIVATE_KEY NULL
#define WITHOUT_SENDER_PUBLIC_KEY_OSSL NULL, 0
#define WITHOUT_PSK NULL, 0, NULL, 0
#define WITHOUT_SENDER_PUBLIC_KEY_GNUTLS NULL

#define PASS 1
#define FAIL -1

#define NUM_TESTS 8

typedef void (*test_func_t)(const keys *);

static struct tests_final_report
{
    char test_name[NUM_TESTS][256];
    char test_result[NUM_TESTS][16];

    int num_tests_run;
} final_report;

typedef struct openssl_sender_gnutls_recipient_test_fixture
{
    uint8_t ossl_hpke_mode;
    const unsigned char *recipient_public_key_raw;
    const size_t recipient_public_key_raw_len;
    EVP_PKEY *sender_private_key;
    const gnutls_privkey_t recipient_private_key;
    const gnutls_pubkey_t sender_public_key;
    const unsigned char *psk;
    const size_t psk_len;
    const unsigned char *psk_id;
    const size_t psk_id_len;
} openssl_sender_gnutls_recipient_test_fixture;

static openssl_sender_gnutls_recipient_test_fixture
init_openssl_sender_gnutls_recipient_fixture(
    uint8_t ossl_hpke_mode, const unsigned char *recipient_public_key_raw,
    size_t recipient_public_key_raw_len, EVP_PKEY *sender_private_key,
    const gnutls_privkey_t recipient_private_key,
    const gnutls_pubkey_t sender_public_key, const unsigned char *psk,
    const size_t psk_len, const unsigned char *psk_id, const size_t psk_id_len)
{
    openssl_sender_gnutls_recipient_test_fixture fixture = {
        .ossl_hpke_mode = ossl_hpke_mode,
        .recipient_public_key_raw = recipient_public_key_raw,
        .recipient_public_key_raw_len = recipient_public_key_raw_len,
        .sender_private_key = sender_private_key,
        .recipient_private_key = recipient_private_key,
        .sender_public_key = sender_public_key,
        .psk = psk,
        .psk_len = psk_len,
        .psk_id = psk_id,
        .psk_id_len = psk_id_len};

    return fixture;
}

int test_openssl_sender_gnutls_recipient(
    const openssl_sender_gnutls_recipient_test_fixture *fixture)
{
    int ret;

    unsigned char *enc = NULL;
    size_t enclen = 0;
    unsigned char *ct = NULL;
    size_t ctlen = 0;
    unsigned char exp[32];
    size_t explen = sizeof(exp);

    ret = openssl_hpke_encap_and_seal(
        fixture->ossl_hpke_mode, fixture->recipient_public_key_raw,
        fixture->recipient_public_key_raw_len, fixture->sender_private_key,
        OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
        OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, fixture->psk, fixture->psk_len,
        fixture->psk_id, info, sizeof(info) - 1, aad, sizeof(aad) - 1, pt,
        sizeof(pt) - 1, &enc, &enclen, &ct, &ctlen, exp, explen);
    if (ret != 1)
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

    gnutls_datum_t *psk_d = NULL;
    gnutls_datum_t *psk_id_d = NULL;

    if (fixture->psk && fixture->psk_id)
    {
        psk_d = &(gnutls_datum_t){.data = (unsigned char *)fixture->psk,
                                  .size = fixture->psk_len};
        psk_id_d = &(gnutls_datum_t){.data = (unsigned char *)fixture->psk_id,
                                     .size = fixture->psk_id_len};
    }

    ret = gnutls_hpke_decap_and_open(
        fixture->recipient_private_key, fixture->sender_public_key,
        GNUTLS_HPKE_KEM_DHKEM_X25519, GNUTLS_HPKE_KDF_HKDF_SHA256,
        GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, psk_d, psk_id_d, &info_d, aad,
        sizeof(aad) - 1, &enc_d, &ct_d, decrypted, &decrypted_len);
    if (ret != 0)
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

    ret = PASS;
    goto cleanup;

fail:
    ret = FAIL;

cleanup:
    OPENSSL_free(enc);
    OPENSSL_free(ct);

    return ret;
}

static void test_openssl_sender_gnutls_recipient_base(const keys *keys)
{
    PRINT_TEST_RUN();

    openssl_sender_gnutls_recipient_test_fixture fixture =
        init_openssl_sender_gnutls_recipient_fixture(
            OSSL_HPKE_MODE_BASE, keys->ossl_recipient_keypair.public_key_raw,
            keys->ossl_recipient_keypair.public_key_raw_len,
            WITHOUT_SENDER_PRIVATE_KEY,
            keys->gnutls_recipient_keypair.private_key,
            WITHOUT_SENDER_PUBLIC_KEY_GNUTLS, WITHOUT_PSK);

    int test_result = test_openssl_sender_gnutls_recipient(&fixture);

    if (test_result == PASS)
    {
        PRINT_TEST_PASS();
        return;
    }

    PRINT_TEST_FAIL();
}

void test_openssl_sender_gnutls_recipient_psk(const keys *keys)
{
    PRINT_TEST_RUN();

    openssl_sender_gnutls_recipient_test_fixture fixture =
        init_openssl_sender_gnutls_recipient_fixture(
            OSSL_HPKE_MODE_PSK, keys->ossl_recipient_keypair.public_key_raw,
            keys->ossl_recipient_keypair.public_key_raw_len,
            WITHOUT_SENDER_PRIVATE_KEY,
            keys->gnutls_recipient_keypair.private_key,
            WITHOUT_SENDER_PUBLIC_KEY_GNUTLS, psk, sizeof(psk) - 1, psk_id,
            sizeof(psk_id) - 1);

    int test_result = test_openssl_sender_gnutls_recipient(&fixture);

    if (test_result == PASS)
    {
        PRINT_TEST_PASS();
        return;
    }

    PRINT_TEST_FAIL();
}

void test_openssl_sender_gnutls_recipient_auth(const keys *keys)
{
    PRINT_TEST_RUN();

    openssl_sender_gnutls_recipient_test_fixture fixture =
        init_openssl_sender_gnutls_recipient_fixture(
            OSSL_HPKE_MODE_AUTH, keys->ossl_recipient_keypair.public_key_raw,
            keys->ossl_recipient_keypair.public_key_raw_len,
            keys->ossl_sender_keypair.pkey,
            keys->gnutls_recipient_keypair.private_key,
            keys->gnutls_sender_keypair.public_key, WITHOUT_PSK);

    int test_result = test_openssl_sender_gnutls_recipient(&fixture);

    if (test_result == PASS)
    {
        PRINT_TEST_PASS();
        return;
    }

    PRINT_TEST_FAIL();
}

void test_openssl_sender_gnutls_recipient_psk_auth(const keys *keys)
{
    PRINT_TEST_RUN();

    openssl_sender_gnutls_recipient_test_fixture fixture =
        init_openssl_sender_gnutls_recipient_fixture(
            OSSL_HPKE_MODE_PSKAUTH, keys->ossl_recipient_keypair.public_key_raw,
            keys->ossl_recipient_keypair.public_key_raw_len,
            keys->ossl_sender_keypair.pkey,
            keys->gnutls_recipient_keypair.private_key,
            keys->gnutls_sender_keypair.public_key, psk, sizeof(psk) - 1,
            psk_id, sizeof(psk_id) - 1);

    int test_result = test_openssl_sender_gnutls_recipient(&fixture);

    if (test_result == PASS)
    {
        PRINT_TEST_PASS();
        return;
    }

    PRINT_TEST_FAIL();
}

typedef struct gnutls_sender_openssl_recipient_test_fixture
{
    uint8_t ossl_hpke_mode;
    const unsigned char *sender_public_key_raw;
    const size_t sender_public_key_raw_len;
    EVP_PKEY *recipient_private_key;
    const gnutls_privkey_t sender_private_key;
    const gnutls_pubkey_t recipient_public_key;
    const unsigned char *psk;
    const size_t psk_len;
    const unsigned char *psk_id;
    const size_t psk_id_len;
} gnutls_sender_openssl_recipient_test_fixture;

static gnutls_sender_openssl_recipient_test_fixture
init_gnutls_sender_openssl_recipient_fixture(
    uint8_t ossl_hpke_mode, const unsigned char *sender_public_key_raw,
    size_t sender_public_key_raw_len, EVP_PKEY *recipient_private_key,
    const gnutls_privkey_t sender_private_key,
    const gnutls_pubkey_t recipient_public_key, const unsigned char *psk,
    const size_t psk_len, const unsigned char *psk_id, const size_t psk_id_len)
{
    gnutls_sender_openssl_recipient_test_fixture fixture = {
        .ossl_hpke_mode = ossl_hpke_mode,
        .sender_public_key_raw = sender_public_key_raw,
        .sender_public_key_raw_len = sender_public_key_raw_len,
        .recipient_private_key = recipient_private_key,
        .sender_private_key = sender_private_key,
        .recipient_public_key = recipient_public_key,
        .psk = psk,
        .psk_len = psk_len,
        .psk_id = psk_id,
        .psk_id_len = psk_id_len};

    return fixture;
}

int test_gnutls_sender_openssl_recipient(
    const gnutls_sender_openssl_recipient_test_fixture *fixture)
{
    int ret;

    gnutls_datum_t info_d = {.data = (unsigned char *)info,
                             .size = (unsigned int)(sizeof(info) - 1)};

    gnutls_datum_t enc = {0};
    gnutls_datum_t cipher_text = {0};

    gnutls_datum_t plain_text = {.data = (unsigned char *)pt,
                                 .size = sizeof(pt) - 1};

    gnutls_datum_t *psk_d = NULL;
    gnutls_datum_t *psk_id_d = NULL;

    if (fixture->psk && fixture->psk_id)
    {
        psk_d = &(gnutls_datum_t){.data = (unsigned char *)fixture->psk,
                                  .size = fixture->psk_len};
        psk_id_d = &(gnutls_datum_t){.data = (unsigned char *)fixture->psk_id,
                                     .size = fixture->psk_id_len};
    }

    ret = gnutls_hpke_encap_and_seal(
        fixture->recipient_public_key, fixture->sender_private_key,
        GNUTLS_HPKE_KEM_DHKEM_X25519, GNUTLS_HPKE_KDF_HKDF_SHA256,
        GNUTLS_HPKE_AEAD_CHACHA20_POLY1305, psk_d, psk_id_d, &info_d, aad,
        sizeof(aad) - 1, &enc, &plain_text, &cipher_text);
    if (ret != 0)
    {
        fprintf(stderr, "GnuTLS encap+seal failed\n");
        goto fail;
    }

    unsigned char decrypted[256];
    size_t decrypted_len = sizeof(decrypted);

    ret = openssl_hpke_decap_and_open(
        fixture->ossl_hpke_mode, fixture->recipient_private_key,
        fixture->sender_public_key_raw, fixture->sender_public_key_raw_len,
        OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256,
        OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, fixture->psk, fixture->psk_len,
        fixture->psk_id, info, sizeof(info) - 1, aad, sizeof(aad) - 1, enc.data,
        enc.size, cipher_text.data, cipher_text.size, decrypted,
        &decrypted_len);
    if (ret != 1)
    {
        fprintf(stderr, "OpenSSL HPKE decap+open failed\n");
        goto fail;
    }

    if (decrypted_len != (sizeof(pt) - 1) ||
        memcmp(decrypted, pt, sizeof(pt) - 1) != 0)
    {
        fprintf(stderr, "PLAINTEXT MISMATCH\n");
        goto fail;
    }

    ret = PASS;
    goto cleanup;

fail:
    ret = FAIL;

cleanup:
    gnutls_free(enc.data);
    gnutls_free(cipher_text.data);

    return ret;
}

void test_gnutls_sender_openssl_recipient_base(const keys *keys)
{
    PRINT_TEST_RUN();

    gnutls_sender_openssl_recipient_test_fixture fixture =
        init_gnutls_sender_openssl_recipient_fixture(
            OSSL_HPKE_MODE_BASE, WITHOUT_SENDER_PUBLIC_KEY_OSSL,
            keys->ossl_recipient_keypair.pkey, WITHOUT_SENDER_PRIVATE_KEY,
            keys->gnutls_recipient_keypair.public_key, WITHOUT_PSK);

    int test_result = test_gnutls_sender_openssl_recipient(&fixture);

    if (test_result == PASS)
    {
        PRINT_TEST_PASS();
        return;
    }

    PRINT_TEST_FAIL();
}

void test_gnutls_sender_openssl_recipient_psk(const keys *keys)
{
    PRINT_TEST_RUN();

    gnutls_sender_openssl_recipient_test_fixture fixture =
        init_gnutls_sender_openssl_recipient_fixture(
            OSSL_HPKE_MODE_PSK, WITHOUT_SENDER_PUBLIC_KEY_OSSL,
            keys->ossl_recipient_keypair.pkey, WITHOUT_SENDER_PRIVATE_KEY,
            keys->gnutls_recipient_keypair.public_key, psk, sizeof(psk) - 1,
            psk_id, sizeof(psk_id) - 1);

    int test_result = test_gnutls_sender_openssl_recipient(&fixture);

    if (test_result == PASS)
    {
        PRINT_TEST_PASS();
        return;
    }

    PRINT_TEST_FAIL();
}

void test_gnutls_sender_openssl_recipient_auth(const keys *keys)
{
    PRINT_TEST_RUN();

    gnutls_sender_openssl_recipient_test_fixture fixture =
        init_gnutls_sender_openssl_recipient_fixture(
            OSSL_HPKE_MODE_AUTH, keys->ossl_sender_keypair.public_key_raw,
            keys->ossl_sender_keypair.public_key_raw_len,
            keys->ossl_recipient_keypair.pkey,
            keys->gnutls_sender_keypair.private_key,
            keys->gnutls_recipient_keypair.public_key, WITHOUT_PSK);

    int test_result = test_gnutls_sender_openssl_recipient(&fixture);

    if (test_result == PASS)
    {
        PRINT_TEST_PASS();
        return;
    }

    PRINT_TEST_FAIL();
}

void test_gnutls_sender_openssl_recipient_psk_auth(const keys *keys)
{
    PRINT_TEST_RUN();

    gnutls_sender_openssl_recipient_test_fixture fixture =
        init_gnutls_sender_openssl_recipient_fixture(
            OSSL_HPKE_MODE_PSKAUTH, keys->ossl_sender_keypair.public_key_raw,
            keys->ossl_sender_keypair.public_key_raw_len,
            keys->ossl_recipient_keypair.pkey,
            keys->gnutls_sender_keypair.private_key,
            keys->gnutls_recipient_keypair.public_key, psk, sizeof(psk) - 1,
            psk_id, sizeof(psk_id) - 1);

    int test_result = test_gnutls_sender_openssl_recipient(&fixture);

    if (test_result == PASS)
    {
        PRINT_TEST_PASS();
        return;
    }

    PRINT_TEST_FAIL();
}

static void shuffle_tests(test_func_t *tests, size_t num_tests)
{
    for (size_t i = num_tests - 1; i > 0; i--)
    {
        size_t j = rand() % (i + 1);
        test_func_t temp = tests[i];
        tests[i] = tests[j];
        tests[j] = temp;
    }
}

void run_all_tests()
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

    test_func_t tests[] = {test_openssl_sender_gnutls_recipient_base,
                           test_openssl_sender_gnutls_recipient_psk,
                           test_openssl_sender_gnutls_recipient_auth,
                           test_openssl_sender_gnutls_recipient_psk_auth,
                           test_gnutls_sender_openssl_recipient_base,
                           test_gnutls_sender_openssl_recipient_psk,
                           test_gnutls_sender_openssl_recipient_auth,
                           test_gnutls_sender_openssl_recipient_psk_auth};

    shuffle_tests(tests, NUM_TESTS);

    for (size_t i = 0; i < NUM_TESTS; i++)
    {
        tests[i](&keys);
    }

cleanup:
    gnutls_kp_deinit(&keys.gnutls_sender_keypair);
    gnutls_kp_deinit(&keys.gnutls_recipient_keypair);
    openssl_kp_deinit(&keys.ossl_sender_keypair);
    openssl_kp_deinit(&keys.ossl_recipient_keypair);

    gnutls_global_deinit();
}

static int is_any_test_failed()
{
    for (int i = 0; i < final_report.num_tests_run; i++)
    {
        if (strcmp(final_report.test_result[i], "FAIL") == 0)
        {
            return 1;
        }
    }
    return 0;
}

static int is_any_test_passed()
{
    for (int i = 0; i < final_report.num_tests_run; i++)
    {
        if (strcmp(final_report.test_result[i], "PASS") == 0)
        {
            return 1;
        }
    }
    return 0;
}

static void print_final_report_passed()
{
    if (!is_any_test_passed())
    {
        return;
    }

    printf("\n==================== PASSED TESTS ===================\n");
    for (int i = 0; i < final_report.num_tests_run; i++)
    {
        if (strcmp(final_report.test_result[i], "PASS") == 0)
        {
            printf("%s: %s\n", final_report.test_name[i],
                   final_report.test_result[i]);
        }
    }
    printf("=====================================================\n");
}

static void print_final_report_failed()
{
    if (!is_any_test_failed())
    {
        return;
    }

    printf("\n==================== FAILED TESTS ===================\n");
    for (int i = 0; i < final_report.num_tests_run; i++)
    {
        if (strcmp(final_report.test_result[i], "FAIL") == 0)
        {
            printf("%s: %s\n", final_report.test_name[i],
                   final_report.test_result[i]);
        }
    }
    printf("=====================================================\n");
}

void print_final_report()
{
    print_final_report_passed();
    print_final_report_failed();
}
