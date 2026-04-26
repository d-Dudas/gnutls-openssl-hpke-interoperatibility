# Overview

This repository contains a benchmarking system to compare GnuTLS HPKE performance with OpenSSL HPKE performance.

The benchmarking system is supposed to benchmark inter-library procedures. This is done by modifying the source code of
each library by measuring the duration of each (sub)procedure and printing it to stdout:
`<library>,<procedure>,<subprocedure>,<duration_in_ms>`. The printed data can be collected to a .csv file to be further
analyzed.

Since the source code of each library needs to be modified, they are submodules of this repository, fixed on the
branches where the benchmarking modifications are done. To reproduce the benchmark resuts, one should build the
libraries from the specified branches and install them to a custom installation path: `(GNUTLS/OPENSSL)_INSTALLATION`.
If these environment variables are defined on your system, you can `source` the .sourceme file to add the paths to
`LD_LIBRARY_PATH` and `PKG_CONFIG_PATH`.

# Building and running thes tests

## To build the binary, simply run:

```bash
make
```

## To run the benchmarks, execute:

```bash
make run
```

This will produce a results.csv file, containing the results (without header).

## To analyze the resulst, execute:

```bash
make analyze
```

This will produce statistics and graphs based on the results.csv
