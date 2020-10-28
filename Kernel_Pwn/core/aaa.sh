#! /bin/sh
gcc exp.c -static -masm=intel -std=c99 -o exp
mv exp core/tmp/
cd core
./gen_cpio.sh ./core.cpio
cp core.cpio ../
cd ..
./start.sh
