#!/bin/bash

# Usage: ./exe-analyze.sh <file> [functions to analyze]

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <file> [functions to analyze]"
    exit 1
fi

FILE="$1"

FUNCTIONS=("${@:2}")

# checksec
if command -v checksec >/dev/null 2>&1; then
    echo "Running checksec on $FILE..."
    checksec "$FILE"
else
    echo "checksec not found. Please install it (e.g., sudo apt install checksec)."
fi

echo ""

# show non-debugging symbols
if command -v readelf >/dev/null 2>&1; then
    echo "Showing symbols in $FILE..."
    readelf -s "$FILE" | grep -E 'FUNC|OBJECT' | grep -v 'UND' | sort -k 2
else
    echo "readelf not found. Please install it (e.g., sudo apt install binutils)."
fi

echo ""

# disassemble functions with GDB
if command -v gdb >/dev/null 2>&1; then
    echo "Disassembling functions in $FILE..."
    gdb -batch -ex "file $FILE" -ex "set pagination off" \
        -ex "set disassembly-flavor intel" \
        -ex "info functions" \
        -ex "disassemble ${FUNCTIONS[@]}" \
        -ex "quit"
else
    echo "GDB not found. Please install it (e.g., sudo apt install gdb)."
fi