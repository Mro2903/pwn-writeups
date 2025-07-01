#!/bin/sh
sshpass -p guest scp -P2222 blackjack@pwnable.kr:* .
cp ../fake_flag flag