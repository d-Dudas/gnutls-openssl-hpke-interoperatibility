#ifndef BENCHMARKER_H
#define BENCHMARKER_H

typedef enum benchmarker_target_hpke_mode
{
    BENCHMARKER_TARGET_HPKE_MODE_BASE,
    BENCHMARKER_TARGET_HPKE_MODE_PSK,
    BENCHMARKER_TARGET_HPKE_MODE_AUTH,
    BENCHMARKER_TARGET_HPKE_MODE_PSKAUTH
} benchmarker_target_hpke_mode;

typedef enum benchmarker_target_library
{
    BENCHMARKER_TARGET_LIBRARY_OPENSSL,
    BENCHMARKER_TARGET_LIBRARY_GNUTLS
} benchmarker_target_library;

typedef enum benchmarker_target_hpke_procedure
{
    BENCHMARKER_TARGET_HPKE_PROCEDURE_KEYGEN,
    BENCHMARKER_TARGET_HPKE_PROCEDURE_ENCAPS,
    BENCHMARKER_TARGET_HPKE_PROCEDURE_DECAPS,
    BENCHMARKER_TARGET_HPKE_PROCEDURE_SEAL,
    BENCHMARKER_TARGET_HPKE_PROCEDURE_OPEN
} benchmarker_target_hpke_procedure;

typedef struct benchmarker_context benchmarker_context;

double benchmarker_get_now(void);

void benchmarker_init(benchmarker_context** ctx);
void benchmarker_deinit(benchmarker_context* ctx);

void benchmarker_set_current_mode(
    benchmarker_context* ctx,
    benchmarker_target_hpke_mode mode);

void benchmarker_set_result(
    benchmarker_context* ctx,
    benchmarker_target_library library,
    benchmarker_target_hpke_procedure procedure,
    double start_time,
    double end_time);

void benchmarker_print_results(benchmarker_context* ctx);

int benchmarker_get_number_of_rounds();

void benchmarker_round_done(benchmarker_context* ctx);

void benchmarker_reset_round(benchmarker_context* ctx);

#endif // BENCHMARKER_H
