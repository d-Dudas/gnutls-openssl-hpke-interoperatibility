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
