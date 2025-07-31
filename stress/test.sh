#! /bin/sh

SERVER=nts1.time.nl

#set -e

for CC in \
    gcc i686-linux-gnu-gcc \
    aarch64-linux-gnu-gcc riscv64-linux-gnu-gcc \
    arm-linux-gnueabi-gcc arm-linux-gnueabihf-gcc \
    s390x-linux-gnu-gcc powerpc64le-linux-gnu-gcc
do          
    make -s -C src clean
    for tls in openssl gnutls; do
    for crypto in openssl nettle gcrypt; do
        echo -n  "[$CC] $tls+$crypto: "
        CC="$CC -fanalyzer" make -s TLS=$tls CRYPTO=$crypto -C src test demo &&
            src/demo "$SERVER" | grep -q 'offset' || (echo production error && false)
    done
    done
done
