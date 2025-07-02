# chess Writeup

## Challenge infos

```text
I heard it takes months to find an MD5 collision...
Challenge is running at: nc pwnable.co.il 9006
```

## Executable analysis
### code analysis
```c
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/md5.h>

char flag_str[0x100];

void init_buffering() {
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);
    alarm(60);
}

int main() {
    init_buffering();
    unsigned char flag_hash[MD5_DIGEST_LENGTH];
    MD5_CTX flag;
    MD5_Init(&flag);
    int fd = open("flag", O_RDONLY);
    int bytes = read(fd, &flag_str, 0x100);
    close(fd);
    MD5_Update(&flag, flag_str, bytes);
    MD5_Final(flag_hash, &flag);
    puts("Flag MD5: ");
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", flag_hash[i]);
    puts("");

    printf("Enter your guess: ");
    char guess_hash[MD5_DIGEST_LENGTH];
    char* guess = malloc(bytes+1);
    bytes = read(0, guess, bytes);
    MD5_CTX guess_ctx;
    MD5_Init(&guess_ctx);
    MD5_Update(&guess_ctx, guess, bytes);
    MD5_Final(guess_hash, &guess_ctx);
    if (!strcmp(flag_hash, guess_hash)) {
        puts("Congrats!!!");
        puts(flag_str);
    } else {
        puts("Wrong!!");
    }
    return 1;
}
```
* the code reads a flag from a file, calculates its MD5 hash, and then waits for the user to input a string.
* it then calculates the MD5 hash of the input string and compares it to the flag's hash.
* if the hashes match, it prints the flag, otherwise it prints "Wrong!!".
### exploit analysis
* the compare funtion is `strcmp`, which compares the two strings and is null-terminated.
```text
Flag MD5: 
537500469ddfc5b29e9379cdcc2f3c86
```
* as we can see the 3rd byte of the hash is `00`, which means that we need to collide with the first three bytes of the hash and not the whole hash.
### Final exploit code
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template hash
from pwn import *
import hashlib

def find_collision(md5_hash):
    collide_with = md5_hash[:3]  # We only need to match the first three bytes
    counter = 0
    while True:
        # Create a test string
        test_string = f"collision_{counter}".encode()
        # Calculate its MD5 hash
        md5_result = hashlib.md5(test_string).digest()
        
        # Check if the first three bytes match the target hash
        if md5_result[:3] == collide_with:
            return test_string
        
        counter += 1

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'hash')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('pwnable.co.il', 9006, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        PIE enabled
# Stripped:   No

io = start()

io.recvline()
flag_hash = unhex(io.recvline().strip())
collision_string = find_collision(flag_hash)
io.send(collision_string)

print(io.recvall(timeout=1).decode())
```
* now, when we run the exploit, we should get a the flag.
```
[+] Opening connection to pwnable.co.il on port 9006: Done
[+] Receiving all data: Done (87B)
[*] Closed connection to pwnable.co.il port 9006
Enter your guess: Congrats!!!
PWNIL{flag_is_here}
```