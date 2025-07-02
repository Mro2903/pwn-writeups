#!/bin/sh
curl -s https://pwnable.co.il/bin/chess.zip -o chess.zip 
unzip -o chess.zip -d .
chmod +x chess
rm chess.zip