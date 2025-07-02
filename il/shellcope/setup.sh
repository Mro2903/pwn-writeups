#!/bin/sh
curl -s https://pwnable.co.il/bin/shellcope.zip -o shellcope.zip 
unzip -o shellcope.zip -d .
chmod +x shellcope
rm shellcope.zip