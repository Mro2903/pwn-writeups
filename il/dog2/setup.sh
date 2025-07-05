#!/bin/sh
curl -s https://pwnable.co.il/bin/dog2.zip -o dog2.zip 
unzip -o dog2.zip -d .
gcc -o dog2 main.c
rm dog2.zip