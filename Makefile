# Makefile for compiling main.c into an executable named main
# It should used the GnuTLS and OpenSSL libraries
# It should be compiled for debugging
# export LD_LIBRARY_PATH=/home/ddudas/projects/gnutls-workspace/.installation/lib:$LD_LIBRARY_PATH
# export PKG_CONFIG_PATH=/home/ddudas/projects/gnutls-workspace/.installation/lib/pkgconfig:$PKG_CONFIG_PATH


SOURCE_FILES = \
	source/main.c \
	source/benchmarker.c \
	source/openssl-wrapper.c \
	source/gnutls-wrapper.c

CC = gcc
CFLAGS = -g -Wall -Wextra

# Add flag for debuggin with gdb
CFLAGS += -ggdb

CUSTOM_GNUTLS_INSTALLATION_PATH = ${GNUTLS_INSTALLATION}
CUSTOM_OPENSSL_INSTALLATION_PATH = ${OPENSSL_INSTALLATION}/lib64

CFLAGS +=  -Iinclude -I$(CUSTOM_GNUTLS_INSTALLATION_PATH)/include -I$(CUSTOM_OPENSSL_INSTALLATION_PATH)/include
LDFLAGS += -L$(CUSTOM_GNUTLS_INSTALLATION_PATH)/lib -L$(CUSTOM_OPENSSL_INSTALLATION_PATH) -lgnutls -lssl -lcrypto

TARGET = tests

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p build
	$(CC) $(CFLAGS) -o build/$(TARGET) $(SOURCE_FILES) $(LDFLAGS)

run: $(TARGET)
	sudo env \
	  LD_LIBRARY_PATH="${GNUTLS_INSTALLATION}/lib:${OPENSSL_INSTALLATION}/lib64:${LD_LIBRARY_PATH}" \
	  PKG_CONFIG_PATH="${GNUTLS_INSTALLATION}/lib/pkgconfig:${OPENSSL_INSTALLATION}/lib64/pkgconfig:${PKG_CONFIG_PATH}" \
	  taskset -c 2 nice -n -20 ./build/tests &> results.csv

analyze: run
	python3 analyze_benchmarks.py results.csv

clean:
	rm -rf build
