# collision writeup

## Challenge infos

```text
Daddy told me about cool MD5 hash collision today.
I wanna do something like that too!

ssh col@pwnable.kr -p2222 (pw:guest)
```

## Server content

```text
--- ls -la ---
total 44
drwxr-x---   5 root col      4096 Apr  2 08:58 .
drwxr-xr-x 118 root root     4096 Jun  1 12:05 ..
d---------   2 root root     4096 Jun 12  2014 .bash_history
-r-xr-sr-x   1 root col_pwn 15164 Mar 26 13:13 col
-rw-r--r--   1 root root      589 Mar 26 13:13 col.c
-r--r-----   1 root col_pwn    26 Apr  2 08:58 flag
dr-xr-xr-x   2 root root     4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root root     4096 Oct 23  2016 .pwntools-cache
--- id ---
uid=1005(col) gid=1005(col) groups=1005(col)
--- cat file---
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                setregid(getegid(), getegid());
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
--- file binary ---
col: setgid ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=48d83f055c56d12dc4762db539bf8840e5b4f6cc, for GNU/Linux 3.2.0, not stripped
```
## Exploitation objective
* The ssh user is ```col```, group ```col```
* The ```flag``` file is readable only by the user ```col_pwn``` or the group ```root```
* The ```col``` binary is a 32bit ELF executable by the ```col_pwn``` user or members of the ```col``` group and is ```suid``` meaning that it executes with the rights of its user even if called by a member of its group

This means that if we pwn the ```col``` executable we can gain read access to the ```flag``` file via suid user ```col_pwn```.

The ```col``` executable is certainly compiled from the ```col.c``` source code, let's have a look.

## C code analysis
```c
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
```

* We need to call the program with a passcode as first argument : ```./fd [passcode]```


```c
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }
```

* The ```[passcode]``` argument should be exactly 20 bytes long, if not the program exits with an error message

```c
        if(hashcode == check_password( argv[1] )){
                setregid(getegid(), getegid());
                system("/bin/cat flag");
                return 0;
        }
```
* The program checks if the ```hashcode``` variable is equal to the return value of the ```check_password()``` function with the ```[passcode]``` argument
* If it is, the program sets the group id of the process to the effective group id and calls ```/bin/cat flag``` to output the content of the ```flag``` file

```c
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}
```
* The ```check_password()``` function takes a pointer to a character array (the passcode) and casts it to an integer pointer
* It then iterates over the first 5 integers of the array (20 bytes = 5 integers of 4 bytes each) and sums them up
* The result is returned as an unsigned long integer

## Hash collisions

* Hash collisions are a situation where two different inputs produce the same hash output
* The ```hashcode``` variable is set to ```0x21DD09EC```, which is the hash we need to produce with the ```check_password()``` function
* The ```check_password()``` function sums the first 5 integers of the input, so we need to find 5 integers that sum up to ```0x21DD09EC```
* because there are a lot of possible combinations of integers that can sum up to the same value, we can create a hash collision by manipulating the input

## Exploitation

* We can create a passcode that is exactly 20 bytes long and produces the same hash output as the ```hashcode``` variable
* We can use the following integers to create a hash collision:
  * ```0x21DD09EC```
  * ```0xEEEEEEEE```
  * ```0x11111112```
  * ```0xEEEEEEEE```
  * ```0x11111112```

* I choose these integers because they have no null bytes in them, which would cause the string to be shorter than 20 bytes when passed to the ```check_password()``` function
* The integers are chosen so that they sum up to ```0x21DD09EC```, which is the value of the ```hashcode``` variable

## Exploitation script

```python
#!/usr/bin/env python
from pwn import *
```
* Use [pwntools](https://github.com/Gallopsled/pwntools) for automatic exploitation
```python
# 5 integer arguments sum to 0x21DD09EC no null bytes
arg = p32(0x21DD09EC) + p32(0xEEEEEEEE) + p32(0x11111112) + p32(0xEEEEEEEE) + p32(0x11111112)
```
* Set the ```arg``` variable to 5 integers that sum to ```0x21DD09EC```, each converted to a 4-byte little-endian representation using ```p32()```
* no null bytes are present in the integers, so the string will be exactly 20 bytes long when passed to the ```check_password()``` function
```python
server = ssh('col', 'pwnable.kr', 2222, 'guest')
io = server.process(['./col', arg])

result = io.recvall()

io.close()
server.close()

print(result)
```
* run the ```col``` executable with the ```arg``` variable as argument
* print the result of the command, which should be the content of the ```flag``` file if the exploitation was successful