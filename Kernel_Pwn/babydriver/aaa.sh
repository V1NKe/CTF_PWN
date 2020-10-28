#!/bin/bash

gcc Bypass_exp.c -static -masm=intel -o exp
mv exp core/tmp
cd core
find . | cpio -o --format=newc > rootfs.cpio
cp rootfs.cpio ../
cd ..
./boot.sh
