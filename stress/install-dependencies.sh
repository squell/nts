#! /bin/sh
export DEBIAN_FRONTEND

for arch in i386 s390x arm64 riscv64 armel armhf ppc64el; do
    dpkg --add-architecture $arch
done

apt-get update

(
    echo ca-certificates make gcc
    for foreign in i686 s390x aarch64 riscv64 powerpc64le; do
        echo gcc-$foreign-linux-gnu
    done
    echo gcc-arm-linux-gnueabi gcc-arm-linux-gnueabihf
    for arch in amd64 i386 s390x arm64 riscv64 armel armhf ppc64el; do
        echo libssl-dev:$arch libgnutls28-dev:$arch libgcrypt20-dev:$arch
    done
) | xargs apt-get install -y
