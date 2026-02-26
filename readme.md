# How to use a custom installation of GnuTLS and OpenSSL

```bash
export LD_LIBRARY_PATH=/home/ddudas/projects/gnutls-workspace/.installation/lib:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/home/ddudas/projects/gnutls-workspace/.installation/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/home/ddudas/projects/gnutls-workspace/.openssl_installation/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/home/ddudas/projects/gnutls-workspace/.openssl_installation/lib64/pkgconfig:$PKG_CONFIG_PATH
```
