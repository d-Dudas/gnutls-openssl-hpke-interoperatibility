#include "gnutls-wrapper.h"
#include "openssl-wrapper.h"

int main(void)
{
    benchmarker_context *ctx;
    benchmarker_init(&ctx);

    for (int i = 0; i < 1000; i++)
    {
        benchmarker_reset_round(ctx);

        run_a11_benchmark(ctx);

        benchmarker_reset_round(ctx);

        run_all_benchmarks(ctx);
    }

    // benchmarker_print_results(ctx);

    benchmarker_deinit(ctx);

    return 0;
}
