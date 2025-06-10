#!/bin/sh
sshpass -p guest scp -P2222 input2@pwnable.kr:* .
cp ../fake_flag flag