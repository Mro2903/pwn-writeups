#!/bin/sh
curl -s https://pwnable.co.il/bin/dog.zip -o dog.zip 
unzip -o dog.zip -d .
gcc -o dog main.c
rm dog.zip