#include "benchmarker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUMBER_OF_ROUNDS 1000
#define NUMBER_OF_LIBRARIES 2
#define NUMBER_OF_MODES 4
#define NUMBER_OF_PROCEDURES 5

typedef struct benchmarker_context
{
    int current_round;
    benchmarker_target_hpke_mode current_mode;
    double results[NUMBER_OF_ROUNDS][NUMBER_OF_LIBRARIES][NUMBER_OF_MODES]
                  [NUMBER_OF_PROCEDURES];
} benchmarker_context;

void benchmarker_init(benchmarker_context **ctx)
{
    *ctx = (benchmarker_context *)malloc(sizeof(benchmarker_context));
    if (*ctx == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for benchmarker context\n");
        return;
    }
    memset(*ctx, 0, sizeof(benchmarker_context));
}

void benchmarker_deinit(benchmarker_context *ctx)
{
    if (ctx)
    {
        free(ctx);
    }
}

void benchmarker_set_current_mode(benchmarker_context *ctx,
                                  benchmarker_target_hpke_mode mode)
{
    if (ctx && mode <= BENCHMARKER_TARGET_HPKE_MODE_PSKAUTH)
    {
        ctx->current_mode = mode;
    }
    else
    {
        fprintf(stderr, "Invalid arguments to benchmarker_set_current_mode\n");
    }
}

void benchmarker_set_result(benchmarker_context *ctx,
                            benchmarker_target_library library,
                            benchmarker_target_hpke_procedure procedure,
                            double start_time, double end_time)
{
    if (!ctx || library > BENCHMARKER_TARGET_LIBRARY_GNUTLS ||
        procedure > BENCHMARKER_TARGET_HPKE_PROCEDURE_OPEN)
    {
        fprintf(stderr, "Invalid arguments to benchmarker_set_result\n");
        return;
    }

    double current_result = end_time - start_time;

    ctx->results[ctx->current_round][library][ctx->current_mode][procedure] +=
        current_result;
}

double benchmarker_get_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000000.0 + (double)ts.tv_nsec;
}

int benchmarker_get_number_of_rounds() { return NUMBER_OF_ROUNDS; }

void benchmarker_round_done(benchmarker_context *ctx)
{
    if (ctx)
    {
        ctx->current_round++;
    }
}

void benchmarker_reset_round(benchmarker_context *ctx)
{
    if (ctx)
    {
        ctx->current_round = 0;
    }
}

double get_average_time(benchmarker_context *ctx,
                        benchmarker_target_library library,
                        benchmarker_target_hpke_mode mode,
                        benchmarker_target_hpke_procedure procedure)
{
    if (!ctx || library > BENCHMARKER_TARGET_LIBRARY_GNUTLS ||
        mode > BENCHMARKER_TARGET_HPKE_MODE_PSKAUTH ||
        procedure > BENCHMARKER_TARGET_HPKE_PROCEDURE_OPEN)
    {
        fprintf(stderr, "Invalid arguments to get_average_time\n");
        return 0.0;
    }

    double total_time = 0.0;
    for (int round = 0; round < ctx->current_round; round++)
    {
        total_time += ctx->results[round][library][mode][procedure];
    }
    return total_time / ctx->current_round;
}

void benchmarker_print_results(benchmarker_context *ctx)
{
    if (!ctx)
    {
        fprintf(stderr, "Invalid argument to benchmarker_print_results\n");
        return;
    }

    const char *mode_names[] = {"BASE", "PSK", "AUTH", "PSKAUTH"};
    const char *procedure_names[] = {"KeyGen", "Encaps", "Decaps", "Seal",
                                     "Open"};

    for (int mode = 0; mode <= BENCHMARKER_TARGET_HPKE_MODE_PSKAUTH; mode++)
    {
        printf("Benchmark results for mode: %s\n", mode_names[mode]);
        printf("%-15s | %-15s | %-15s | %-15s\n", "", "OpenSSL (us)",
               "GnuTLS (us)", "OpenSSL/GnuTLS");
        printf("%-15s-+-%-15s-+-%-15s-+-%-15s\n", "", "---------------",
               "---------------", "------------------");

        for (int procedure = 0;
             procedure <= BENCHMARKER_TARGET_HPKE_PROCEDURE_OPEN; procedure++)
        {
            double openssl_time = get_average_time(
                ctx, BENCHMARKER_TARGET_LIBRARY_OPENSSL, mode, procedure);
            double gnutls_time = get_average_time(
                ctx, BENCHMARKER_TARGET_LIBRARY_GNUTLS, mode, procedure);
            double ratio = gnutls_time > 0 ? openssl_time / gnutls_time : 0;

            printf("%-15s | %-15.2f | %-15.2f | %-15.2f x\n",
                   procedure_names[procedure], openssl_time, gnutls_time,
                   ratio);
        }
        printf("==============================================================="
               "========\n");
    }
}
