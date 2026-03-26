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

CUSTOM_GNUTLS_INSTALLATION_PATH = /home/ddudas/projects/gnutls-workspace/.installation
CUSTOM_OPENSSL_INSTALLATION_PATH = /home/ddudas/projects/gnutls-workspace/.openssl_installation/lib64

CFLAGS +=  -Iinclude -I$(CUSTOM_GNUTLS_INSTALLATION_PATH)/include -I$(CUSTOM_OPENSSL_INSTALLATION_PATH)/include
LDFLAGS += -L$(CUSTOM_GNUTLS_INSTALLATION_PATH)/lib -L$(CUSTOM_OPENSSL_INSTALLATION_PATH) -lgnutls -lssl -lcrypto

TARGET = tests

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p build
	$(CC) $(CFLAGS) -o build/$(TARGET) $(SOURCE_FILES) $(LDFLAGS)

run: $(TARGET)
	./build/$(TARGET)

clean:
	rm -rf build
