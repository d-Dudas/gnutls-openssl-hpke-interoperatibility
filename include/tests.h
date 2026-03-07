#ifndef TESTS_H
#define TESTS_H

#include <gnutls/abstract.h>

typedef struct evp_pkey_st EVP_PKEY;

void run_all_tests(void);

void print_final_report(void);

#endif // TESTS_H
