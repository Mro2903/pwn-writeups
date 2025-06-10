# input2 Writeup

## Challenge infos

```text
Mom? how can I pass my input to a computer program?

ssh input2@pwnable.kr -p2222 (pw:guest)
```

## Server content

```text
--- ls -la ---
total 48
drwxr-x---   5 root input2      4096 Apr  2 09:02 .
drwxr-xr-x 118 root root        4096 Jun  1 12:05 ..
d---------   2 root root        4096 Jun 30  2014 .bash_history
-r--r-----   1 root input2_pwn    45 Apr  2 09:02 flag
-r-xr-sr-x   1 root input2_pwn 16720 Apr  1 13:27 input2
-rw-r--r--   1 root root        1787 Apr  1 13:27 input2.c
dr-xr-xr-x   2 root root        4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root root        4096 Oct 23  2016 .pwntools-cache
--- id ---
uid=1014(input2) gid=1014(input2) groups=1014(input2)
--- cat file---
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
        printf("Welcome to pwnable.kr\n");
        printf("Let's see if you know how to give input to program\n");
        printf("Just give me correct inputs then you will get the flag :)\n");

        // argv
        if(argc != 100) return 0;
        if(strcmp(argv['A'],"\x00")) return 0;
        if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
        printf("Stage 1 clear!\n");

        // stdio
        char buf[4];
        read(0, buf, 4);
        if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
        read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
        printf("Stage 2 clear!\n");

        // env
        if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
        printf("Stage 3 clear!\n");

        // file
        FILE* fp = fopen("\x0a", "r");
        if(!fp) return 0;
        if( fread(buf, 4, 1, fp)!=1 ) return 0;
        if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
        fclose(fp);
        printf("Stage 4 clear!\n");

        // network
        int sd, cd;
        struct sockaddr_in saddr, caddr;
        sd = socket(AF_INET, SOCK_STREAM, 0);
        if(sd == -1){
                printf("socket error, tell admin\n");
                return 0;
        }
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons( atoi(argv['C']) );
        if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
                printf("bind error, use another port\n");
                return 1;
        }
        listen(sd, 1);
        int c = sizeof(struct sockaddr_in);
        cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
        if(cd < 0){
                printf("accept error, tell admin\n");
                return 0;
        }
        if( recv(cd, buf, 4, 0) != 4 ) return 0;
        if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
        printf("Stage 5 clear!\n");

        // here's your flag
        setregid(getegid(), getegid());
        system("/bin/cat flag");
        return 0;
}

--- file binary ---
input2: setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b74679bb85f0f41f9d4c22dc274ca11d6b62b460, for GNU/Linux 3.2.0, not stripped
```
## Exploitation objective
* The ssh user is ```input2```, group ```input2```
* The ```flag``` file is readable only by the user ```input2_pwn``` or the group ```root```
* The ```input2``` binary is a 32bit ELF executable by the ```input2_pwn``` user or members of the ```input2``` group and is ```suid``` meaning that it executes with the rights of its user even if called by a member of its group

This means that if we pwn the ```input2``` executable we can gain read access to the ```flag``` file via suid user ```input2_pwn```.

The ```input2``` executable is certainly compiled from the ```input2.c``` source code, let's have a look.

## C code analysis

```c
	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	
```
* The program expects exactly 100 arguments to be passed to it.
* It checks if the 65th argument (index 'A') is equal to a null byte (`\x00`), and if the 66th argument (index 'B') is equal to the bytes `\x20\x0a\x0d` (space, newline, carriage return). If these conditions are not met, the program exits.

```c
        // stdio
        char buf[4];
        read(0, buf, 4);
        if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
        read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
        printf("Stage 2 clear!\n");

```
* The program reads 4 bytes from standard input (file descriptor 0) and checks if they match the bytes `\x00\x0a\x00\xff`. If not, it exits.
* It then reads 4 bytes from standard error (file descriptor 2) and checks if they match the bytes `\x00\x0a\x02\xff`. If not, it exits.

```c
        // env
        if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
        printf("Stage 3 clear!\n");
```
* The program checks if the environment variable `\xde\xad\xbe\xef` is set to the value `\xca\xfe\xba\xbe`. If not, it exits.

```c
        // file
        FILE* fp = fopen("\x0a", "r");
        if(!fp) return 0;
        if( fread(buf, 4, 1, fp)!=1 ) return 0;
        if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
        fclose(fp);
        printf("Stage 4 clear!\n");
```
* The program attempts to open a file named `\x0a` (which is a newline character) for reading. If it fails to open the file, it exits.
* It reads 4 bytes from the file and checks if they match the bytes `\x00\x00\x00\x00`. If not, it exits.

```c
        // network
        int sd, cd;
        struct sockaddr_in saddr, caddr;
        sd = socket(AF_INET, SOCK_STREAM, 0);
        if(sd == -1){
                printf("socket error, tell admin\n");
                return 0;
        }
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons( atoi(argv['C']) );
        if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
                printf("bind error, use another port\n");
                return 1;
        }
        listen(sd, 1);
        int c = sizeof(struct sockaddr_in);
        cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
        if(cd < 0){
                printf("accept error, tell admin\n");
                return 0;
        }
        if( recv(cd, buf, 4, 0) != 4 ) return 0;
        if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
        printf("Stage 5 clear!\n");
```
* The program creates a TCP socket and binds it to a port specified by the 67th argument (index 'C').
* It listens for incoming connections and accepts one connection.
* It then reads 4 bytes from the connected socket and checks if they match the bytes `\xde\xad\xbe\xef`. If not, it exits.

```c
        // here's your flag
        setregid(getegid(), getegid());
        system("/bin/cat flag");
        return 0;
```
* If all previous stages are cleared, the program sets the group ID of the process to the effective group ID and executes the command `/bin/cat flag`, which reads the content of the `flag` file.

## python script

```python
#!/usr/bin/env python
from pwn import *
import os
```
* Use [pwntools](https://github.com/Gallopsled/pwntools) for automatic exploitation
* Import the `os` module to manipulate environment variables and more
```python
args = [b'\x00']*100
args[ord('B')] = '\x20\x0a\x0d'
args[ord('C')] = '12345'
```
* Create a list of 100 bytes, initialized to null bytes (`\x00`)
* Set the 66th argument (index 'B') to the bytes `\x20\x0a\x0d` (space, newline, carriage return)
* Set the 67th argument (index 'C') to the string `'12345'`, which will be used as the port number for the socket
```python
r1, w1 = os.pipe()
r2, w2 = os.pipe()
os.write(w1, b'\x00\x0a\x00\xff')
os.write(w2, b'\x00\x0a\x02\xff')
```
* Create two pipes for inter-process communication
* Write the bytes `\x00\x0a\x00\xff` to the first pipe (standard input)
* Write the bytes `\x00\x0a\x02\xff` to the second pipe (standard error)

```python
with open('\x0a', 'wb') as f:
	f.write(b'\x00\x00\x00\x00')
```
* Open a file named `\x0a` (newline character) for writing in binary mode
* Write the bytes `\x00\x00\x00\x00` to the file

```python
p = process(executable='input2', 
	    argv=args, 
	    stdin=r1, stderr=r2, 
	    env={'\xde\xad\xbe\xef' :'\xca\xfe\xba\xbe'})
```
* Create a new process to run the `input2` executable
* Pass the arguments, standard input, standard error, and environment variables to the process

```python
conn = remote('localhost', 12345)
conn.sendline('\xde\xad\xbe\xef')
```
* Create a remote connection to the localhost on port `12345`
* Send the bytes `\xde\xad\xbe\xef` to the remote connection, which is expected by the program

```python
result = p.recvall()
p.close()
conn.close()
print(result.decode('utf-8'))
```
* Receive all output from the process and close the process and remote connection
* Print the result, which should contain the content of the `flag` file if all stages are cleared successfully

## shell script
* because the script needs to run on the remote server, we need to create a shell script that will run the python script
```bash
# Copy exploit.py and run it remotely
sshpass -p "$PASS" ssh -p "$PORT" -o StrictHostKeyChecking=no "$USER@$HOST" "
TMPDIR=\$(mktemp -d)
cd \"\$TMPDIR\"
for f in \$HOME/*; do
    ln -s \"\$f\" .
done
echo \$TMPDIR
exit
" > tmpdir.txt
TMPDIR=$(cat tmpdir.txt)
rm tmpdir.txt
```
* Use `sshpass` to log in to the remote server and create a temporary directory
* create symbolic links to all files in the home directory in the temporary directory
```bash
# Copy the exploit script to the remote server and execute it
sshpass -p "$PASS" scp -P "$PORT" "$LOCAL_EXPLOIT" "$USER@$HOST:$TMPDIR/exploit.py"
sshpass -p "$PASS" ssh -p "$PORT" "$USER@$HOST" "cd $TMPDIR && python exploit.py"
```
* Use `sshpass` to copy the exploit script to the remote server and execute it in the temporary directory