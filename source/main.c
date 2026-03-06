#include "tests.h"
#include "utils.h"

#include <string.h>

int main(void)
{
    int ret = 1;
    openssl_x25519_keypair_t ossl_sender_keypair;
    openssl_x25519_keypair_t ossl_recipient_keypair;
    gnutls_x25519_keypair_t gnutls_sender_keypair;
    gnutls_x25519_keypair_t gnutls_recipient_keypair;

    memset(&ossl_sender_keypair, 0, sizeof(ossl_sender_keypair));
    memset(&ossl_recipient_keypair, 0, sizeof(ossl_recipient_keypair));
    memset(&gnutls_sender_keypair, 0, sizeof(gnutls_sender_keypair));
    memset(&gnutls_recipient_keypair, 0, sizeof(gnutls_recipient_keypair));

    ret = gnutls_global_init();
    if (ret != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "gnutls_global_init failed\n");
        return 1;
    }

    ret = generate_keypair(&ossl_sender_keypair, &gnutls_sender_keypair);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to generate sender keypair\n");
        goto cleanup;
    }

    ret = generate_keypair(&ossl_recipient_keypair, &gnutls_recipient_keypair);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to generate recipient keypair\n");
        goto cleanup;
    }

    ret = test_openssl_sender_gnutls_recipient(&ossl_sender_keypair,
                                               &gnutls_sender_keypair);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    gnutls_kp_deinit(&gnutls_sender_keypair);
    openssl_kp_deinit(&ossl_sender_keypair);

    gnutls_global_deinit();

    return ret;
}
