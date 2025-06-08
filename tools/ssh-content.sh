#!/bin/bash

# Usage: ./ssh-contend.sh <user> <password> <file1> [file2] [file3] ...

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <user> <password> <file1> [file2] ..."
    exit 1
fi

USER="$1"
PASSWORD="$2"
shift 2

FILES=("$@")

# Install sshpass if not present
if ! command -v sshpass >/dev/null 2>&1; then
    echo "sshpass not found. Please install it (e.g., sudo apt install sshpass)."
    exit 2
fi

sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -p 2222 "$USER"@pwnable.kr "
    echo '--- ls -la ---'
    ls -la
    echo '--- id ---'
    id
    for f in ${FILES[@]}; do
        binary=\"\${f%%.*}\"
        echo '--- cat file---'
        cat \"\$f\"
        echo '--- file binary ---'
        file \"\$binary\"
    done
"