#include "benchmark.h"
#include "tests.h"

int main(void)
{
    run_all_tests();

    print_final_report();

    run_all_benchmarks();

    print_benchmarks_report();

    return 0;
}
