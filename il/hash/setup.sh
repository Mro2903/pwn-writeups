#!/bin/sh
curl -s https://pwnable.co.il/bin/hash.zip -o hash.zip 
unzip -o hash.zip -d .
gcc -o hash hash.c -lssl -lcrypto -lz -lzstd
echo -n "PWNIL{fake_flag_for_hash}" > flag
rm hash.zip