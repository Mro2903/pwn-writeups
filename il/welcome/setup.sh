#!/bin/sh
curl -s https://pwnable.co.il/bin/welcome.zip -o welcome.zip
unzip -o welcome.zip -d .
rm welcome.zip