#!/bin/sh
gcc exp.c -static -lpthread -std=c99 -o exp
mv exp baby/
cd baby
find . | cpio -o --format=newc > core.cpio
cp core.cpio ../
cd ..
./start.sh
