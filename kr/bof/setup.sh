#!/bin/sh
sshpass -p guest scp -P2222 bof@pwnable.kr:* .
cp ../fake_flag flag