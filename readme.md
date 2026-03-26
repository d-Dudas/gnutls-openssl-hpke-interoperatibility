# Overview

This repository contains some HPKE interoperability tests between GnuTLS and OpenSSL.

Since the HPKE implementation is not yet available in the main branch of GnuTLS (and it is also still under
development), a custom installation of GnuTLS might be required to run the tests.

For debugging purposes, I've also used a custom installation of OpenSSL, which allowed me to add extra logs to the HPKE
implementation.

> The makefile contains the paths to the custom installations of both GnuTLS and OpenSSL I've used. In order to build
> and run the tests, the modifications of makefile might be required.

# How to use a custom installation of GnuTLS and OpenSSL

Without updating 'LD_LIBRARY_PATH' and 'PKG_CONFIG_PATH' environment variables, the system will use the default
installations of GnuTLS and OpenSSL, which might not contain the HPKE implementation.

```bash
export LD_LIBRARY_PATH=/home/ddudas/projects/gnutls-workspace/.installation/lib:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/home/ddudas/projects/gnutls-workspace/.installation/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/home/ddudas/projects/gnutls-workspace/.openssl_installation/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/home/ddudas/projects/gnutls-workspace/.openssl_installation/lib64/pkgconfig:$PKG_CONFIG_PATH
```

# Building and running thes tests

To build the tests, simply run:

```bash
make
```

To run the tests, execute:

```bash
make run
```

# History

## 2026.03.07 - Before GnuTLS API rework and performance optimizations

```
==================== BENCHMARKS ===================
bench_gnutls_sender_base:       92029.17 ms
bench_openssl_recipient_base:   30414.65 ms
bench_gnutls_recipient_base:    52281.48 ms
bench_openssl_sender_base:      62577.47 ms
================================================
```

## 2026.03.08 - After GnuTLS API rework

```
=============================== BENCHMARKS =============================
                | OpenSSL         | GnuTLS          | OpenSSL/GnuTLS   |
----------------+-----------------+-----------------+------------------+
Encapsulation   | 60.02        us | 91.61        us | 0.66           x |
Seal            | 0.59         us | 0.28         us | 2.09           x |
Decapsulation   | 29.54        us | 51.64        us | 0.57           x |
Open            | 0.51         us | 0.34         us | 1.47           x |
========================================================================
```

## 2026.03.26 - After benchmarker rework

```
Benchmark results for mode: BASE
                | OpenSSL (us)    | GnuTLS (us)     | OpenSSL/GnuTLS
               -+-----------------+-----------------+-------------------
KeyGen          | 26616.75        | 51398.90        | 0.52            x
Encaps          | 54835.41        | 103290.38       | 0.53            x
Decaps          | 29936.35        | 52134.73        | 0.57            x
Seal            | 397.44          | 252.49          | 1.57            x
Open            | 682.60          | 232.55          | 2.94            x
=======================================================================
Benchmark results for mode: PSK
                | OpenSSL (us)    | GnuTLS (us)     | OpenSSL/GnuTLS
               -+-----------------+-----------------+-------------------
KeyGen          | 25050.62        | 50169.52        | 0.50            x
Encaps          | 54735.58        | 101416.15       | 0.54            x
Decaps          | 29954.52        | 51616.00        | 0.58            x
Seal            | 376.63          | 238.79          | 1.58            x
Open            | 674.40          | 231.47          | 2.91            x
=======================================================================
Benchmark results for mode: AUTH
                | OpenSSL (us)    | GnuTLS (us)     | OpenSSL/GnuTLS
               -+-----------------+-----------------+-------------------
KeyGen          | 25018.33        | 49760.06        | 0.50            x
Encaps          | 78424.41        | 150883.78       | 0.52            x
Decaps          | 54353.79        | 101165.83       | 0.54            x
Seal            | 383.05          | 254.38          | 1.51            x
Open            | 679.88          | 230.02          | 2.96            x
=======================================================================
Benchmark results for mode: PSKAUTH
                | OpenSSL (us)    | GnuTLS (us)     | OpenSSL/GnuTLS
               -+-----------------+-----------------+-------------------
KeyGen          | 25027.74        | 50060.63        | 0.50            x
Encaps          | 78446.40        | 153393.74       | 0.51            x
Decaps          | 54291.36        | 104174.42       | 0.52            x
Seal            | 384.67          | 257.15          | 1.50            x
Open            | 677.58          | 235.52          | 2.88            x
=======================================================================
```
