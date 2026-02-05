---
date: "2025-04-06"
description: "Writeups for a CTF i participated solo in and placed 1st!"
---

# LLM summer :-

![image.png](image.png)

```python
AKTH{T00_L1TTLE_7RUS7}
```

# Forensics :-

## Andor’s Systematic Corruption

Opening the file in a hex viewer

![image.png](image%201.png)

we can see some strings where there should be 00 bytes 
we know that xorring the text with itself gives us the null bytes so we can try bruteforcing the xor key as we know the first header of a png is  89 50 4E 47 0D 0A 1A 0A 

Using this script:- 

```python
def derive_key(ciphertext, key_length, header):
    key = bytearray(key_length)
    for i in range(len(header)):
        key[i % key_length] = ciphertext[i] ^ header[i]
    return bytes(key)

def test_key(ciphertext, key):
    dec = bytes([b ^ key[i % len(key)] for i, b in enumerate(ciphertext[:128])])
    chunks = [b'IHDR', b'IDAT', b'IEND', b'pHYs', b'tEXt']
    for i in range(len(dec) - 4):
        if dec[i:i+4] in chunks:
            return True, dec
    return False, dec

def main():
    header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    with open("andor_flag.png", "rb") as f:
        data = f.read()

    for key_len in range(1, 17):
        key = derive_key(data, key_len, header)
        if bytes([data[i] ^ key[i % key_len] for i in range(len(header))]) != header:
            continue
        ok, sample = test_key(data, key)
        if ok:
            print("Key length:", key_len)
            print("Key (hex):", key.hex())
            with open(f"decrypted_{key_len}.png", "wb") as out:
                out.write(bytes([b ^ key[i % key_len] for i, b in enumerate(data)]))
            break

main()

```

We get the output file

![decrypted_5.png](decrypted_5.png)

```python
AKTH{c0rrupt10n_15_b4d}
```

## Fangs

we are given a large jpg file

if we look into its exif data we can see the following

![image.png](image%202.png)

from this we can makeout that the last characters of the exif tags makeup our flag so we extract all and we get 

nKH{a_g__TAm_a}

since we know the flag format

AKTH{}

after replacing we are left with AKTH{a_g_a_m_n}

using the name of the challenge as Fangs we can see it is hinting at FAANG which we know after facebook changed its name to meta is known as MAANG we get our flag

```python

AKTH{m_a_a_n_g}
```

## **I got bored and can't make another challenge name**

we are given 14 flag files inside a zip files so after extracting it we just run

```python
zsteg -a image_*
```

and we can see the flag in the first image itself 

![image.png](image%203.png)

so just reverse in python

![image.png](image%204.png)

```python
AKTH{FOLLOW_PIXEL_CLUB}
```

# OSINT

## **Unmarked Rural Roads**

initially started by searching for Bright Home Public School we can see there is one nearby Ashoka University which is in Haryana Sonepat

![image.png](image%205.png)

So just bruteforcing nearby locations we get our flag as

```python
AKTH{asawarpur}
```

## **Mr. India**

We start by reverse searching the image and see its a loaction in ashoka university itself

![image.png](image%206.png)

we go here and see the virtual tour of the campus

![image.png](image%207.png)

we “change our angle” and see the name we need on the nameplate making the flag 

```python
AKTH{priyank_narayan}
```

# WEB

## **Not Just Bots**

simply going to the robots.txt file, as suggested by the title and the description  on the website. we get our flag 

![image.png](image%208.png)

```python
AKTH{n0t_11ms.txt} 
```

## **Legion**

Not sure if this was the intended way to solve as the hint suggests otherwise but 

first off removing the cookie header from the request we can see the response

![image.png](image%209.png)

we start by going to /onions on the site

changing our useragent to be Tor’s useragent and lastly adding the dnt:1 header in our request gives us the flag

![Screenshot 2025-04-06 105057.png](Screenshot_2025-04-06_105057.png)

```python
AKTH{v33_h4v3_14y3r5_2}
```

## **Holding the line**

Welcome, Agent. There's a call waiting for you on the phone, the number's 65432. You know the address well.

hmm since we know the address well its probably the CTF sites address only and on port 65432

![image.png](image%2010.png)

we can see the server is responding us with Marco in different time intervals each time we send “Polo”

so we can write a script to track the time taken between each iteration

Using this script

```python
import socket
import time

HOST = 'ctf.ieee-ashoka.in'
PORT = 65432

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = s.recv(1024)
        print(f"Received: {data.decode().strip()}")
        for i in range(200):  
            start = time.time()
            s.sendall(b'Polo\n')  
            data = s.recv(1024)
            end = time.time()

            response = data.decode().strip()
            duration = end - start
            print(f"iteration {i+1}: Received '{response}' in {duration:.4f} seconds")

main()

```

we can see the output from the server as

![image.png](image%2011.png)

Something like this so we can see its either 1.xx seconds or 0.xx seconds or 3.xx seconds

so we can map these as 

```python
01310131300031011031130000130103101031111130110311111301003111111310110
```

seeing as we have the least amount of 3’s they probably correspond to spaces so lets change that

now we have

```python
01 101 1 000 10110 11 00001 010 1010 11111 0110 11111 0100 111111 10110
```

which is morso code for

```python
AKTS(M4RC0P0L�(
```

not quite right but we can see what the author was going for with the flag so after fixing it up a bit we have

```python
AKTH(M4RC0P0L0}
```

## **Daddy Issues**

opening up the request in burpsuite

![image.png](image%2012.png)

we can see that there is a hidden url at the end of the servers response

and from the link on the page at the top we first get here

![image.png](image%2013.png)

decoding that string from base64 gives us 

159.89.175.173:63453

from where we get our static_key.pem file which we use to decode the capture file we got from 

![image.png](image%2014.png)

opening the pcap file in wireshark and going to prefrences

![image.png](image%2015.png)

then setting the file as the key here

then refreshing wireshark after hitting apply and searching for the string AKTH{ 

we get

![image.png](image%2016.png)

```python
AKTH{jawWired}
```

## **Fib's Eve**

### will not bore you with the WHOLE PROCESS of getting to the flag this one was a really guessy/farfetched one so here is the solution

the 2 sequences we are looking for are 

fibonacci sequence and the sieve of eratosthenes 

so fib and s eve

then from here we get that that the pages we need to select are from the fib sequence so and the description tells us to skip 6 so we skip the first six and start from the 8th page which is the because 8 is 7th in fib sequence so we start from 8th we have

(The reason for picking fib as the pages is also that there are total 46368 pages which is not a prime and a term of the fib series)

![image.png](image%2017.png)

alot to take in but basically we can spot some fragments of the flag that are not supposed to be a part of base64 charset which are { _ } these

so we can make many guesses and finally reach the solution that we have to use the sieve of eratosthenes (just primes)  as our indexes as the characters are on indexes which are prime numbers so writing a pretty basic script we can achieve this

[fib_pages.txt](fib_pages.txt)

```python
def sieve(n):
    primes = [True] * (n + 1)
    primes[0] = primes[1] = False
    p = 2
    while p * p <= n:
        if primes[p]:
            for i in range(p * p, n + 1, p):
                primes[i] = False
        p += 1
    return [i for i, is_prime in enumerate(primes) if is_prime]
    #sieve to be fancy :P

max_lines = 500 
primes = sieve(4000)[:max_lines]

with open("fib_pages.txt", "r") as f:
    lines = [line.strip() for line in f if line.strip()]

result = []
for i, line in enumerate(lines):
    if i < len(primes):
        prime_index = primes[i]
        if prime_index < len(line):
            result.append(line[prime_index])

final_string = ''.join(result)
print(final_string)
```

we get a string 

```python
W8WH8mAKTH{5ub4n_pr0uD}Al
```

skipping the first 6 and removing the padding at the end we have our flag

```python
AKTH{5ub4n_pr0uD}
```

## LAST wave too lazy to categorize now: -

## AI Winter

found that the response from the AI had trailing hidden characters

got that we have to convert it into tabs and spaces because the challenge was clearly hinting at “stegsnow”

Now for the way in which we had to replace the tabs and spaces for the unicode characters i just wrote a bruteforce script with chatgpt xd.

```python
import os
import re
from pathlib import Path

invisible = """the strings here of unicode characters"""
binary = ""
for char in invisible:
    if char == '\u200c':
        binary += '0'
    elif char == '\u200d':  
        binary += '1'

out_dir = Path("grids")
out_dir.mkdir(exist_ok=True)
count = 0
for rows in range(1, 21):
    for cols in range(1, 201):
        if rows * cols > len(binary):
            continue

        sliced = binary[:rows * cols]
        lines = [
            ''.join(
                '\u200c' if bit == '0' else '\u200d'
                for bit in sliced[r*cols:(r+1)*cols]
            ) for r in range(rows)
        ]

        replaced = "\n".join(
            line.replace('\u200c', ' ').replace('\u200d', '\t')
            for line in lines
        )

        file_path = out_dir / f"grid{rows}x{cols}.txt"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(replaced)
        count += 1

print(f":bricks: Generated {count} grid files in {out_dir}/") 
```

Now also wrote a simple bashscript to run stegsnow on all the grids that were created 
this is way faster than just guessing.

```python
for file in grid*; do
echo "checking: $file"
stegsnow -C "$file"
done
```

then we get our flag

```python
AKTH{SN0-W4Y} #could not be exact becausee i no longer have the chall file xd the site was taken down when writing this
```

## Deep

run binwalk on the image to extract a zip file from it that is password locked

in the exifdata of the image we can also see a google drive link

on the google drive link we find an X account

the X account has some seemingly random information but we can make a guess that this information is used to build up a wordlist (I have solved a similar challenge before)
build a wordlist using
samuel, Ameera and 1995 as the birth year

bruteforce the zip with the created wordlist

After finding the correct password we have 2 files 

file1.txt and file2.txt 

they are almost the same but searching AKTH{ in file 2 gives back a result

so we take the difference of the two files (so the only unique characters)

and we find our flag

```python
AKTH{w0rdl15t_m4g1c} #not sure same reason as above 
```

Crypto 

not going to explain the whole thing but

we dont have to check for block 0 as we know it should be 

AKTH so bruteforcing it we also see that it corresponds to the k1lo function

we run this code to find it for d3lt4

```python
import itertools
from fractions import Fraction as F

# Function Definitions
def d3lt4(msg_x1):
    if len(msg_x1) == 1:
        return ord(msg_x1)
    msg_x1 = msg_x1[::-1]
    _countdown = len(msg_x1) - 1
    vX, vY = F(ord(msg_x1[0]), _countdown).denominator, F(ord(msg_x1[0]), _countdown).numerator
    _countdown -= 1
    for idx in range(1, len(msg_x1) - 1):
        x = ord(msg_x1[idx]) + F(vX, vY)
        vY, vX = x.denominator, x.numerator
        vX, vY = vY, _countdown * vX
        _countdown -= 1
    x = ord(msg_x1[-1]) + F(vX, vY)
    vX, vY = x.denominator, x.numerator
    return (vY, vX)

def k1lo(msg_b2):
    if len(msg_b2) == 1:
        return ord(msg_b2)
    msg_b2 = msg_b2[::-1]
    pwr = (-1) ** len(msg_b2)
    f_ = F(ord(msg_b2[0]), pwr)
    a1, b2 = f_.denominator, f_.numerator
    pwr *= -1
    for idx in range(1, len(msg_b2) - 1):
        temp = ord(msg_b2[idx]) + F(a1, b2)
        b2, a1 = temp.denominator, temp.numerator
        a1, b2 = b2, pwr * a1
        pwr *= -1
    temp = ord(msg_b2[-1]) + F(a1, b2)
    a1, b2 = temp.denominator, temp.numerator
    return (b2, a1)

def zx9t(msg_c3):
    if len(msg_c3) == 1:
        return ord(msg_c3)
    msg_c3 = msg_c3[::-1]
    chaos = (-1) ** int(F(len(msg_c3), len(msg_c3)**2))
    start = F(ord(msg_c3[0]), chaos)
    l1, l2 = start.denominator, start.numerator
    chaos **= -1
    chaos = int(chaos)
    for idx in range(1, len(msg_c3) - 1):
        res = ord(msg_c3[idx]) + F(l1, l2)
        l2, l1 = res.denominator, res.numerator
        l1, l2 = l2, chaos * l1
        chaos **= -1
        chaos = int(chaos)
    final = ord(msg_c3[-1]) + F(l1, l2)
    l1, l2 = final.denominator, final.numerator
    return (l2, l1)

# Data
tuples = [(29490244, 453603), (28735866, 233597), (59585246, 551617), 
          (113048061, 1076555), (65009469, 969989)]
remaining_tuples = tuples[1:]
chars = [chr(i) for i in range(32, 127)]
functions = [d3lt4, k1lo, zx9t]
func_names = ["d3lt4", "k1lo", "zx9t"]

# Start with known prefix
flag = "AKTH{"
segments = ["AKTH"]
counts = {"d3lt4": 0, "k1lo": 1, "zx9t": 0}  # k1lo used once

# Build flag incrementally
for i, target in enumerate(remaining_tuples, 1):
    candidates = []
    if i == 1:  # Second segment starts with '{'
        for s in itertools.product(chars, repeat=3):
            seg = "{" + ''.join(s)
            for j, func in enumerate(functions):
                if func(seg) == target and (func_names[j] != "d3lt4" or counts["d3lt4"] < 2) and \
                   (func_names[j] != "k1lo" or counts["k1lo"] < 2) and \
                   (func_names[j] != "zx9t" or counts["zx9t"] < 1):
                    candidates.append((seg, func_names[j]))
    else:  # Full 4-char segments
        for s in itertools.product(chars, repeat=4):
            seg = ''.join(s)
            for j, func in enumerate(functions):
                if func(seg) == target and (func_names[j] != "d3lt4" or counts["d3lt4"] < 2) and \
                   (func_names[j] != "k1lo" or counts["k1lo"] < 2) and \
                   (func_names[j] != "zx9t" or counts["zx9t"] < 1):
                    candidates.append((seg, func_names[j]))
    
    # Select candidate (highest "confidence" = first match)
    if candidates:
        seg, func_name = candidates[0]  # Could rank by flag-like properties
        flag += seg
        segments.append(seg)
        counts[func_name] += 1
        print(f"Tuple {i}: {seg} with {func_name}, Flag so far: {flag}")
    else:
        print(f"No match for tuple {i}")
        break

# Finalize flag
flag += "}"
print("Final Flag:", flag)
print("Function counts:", counts)
```

From this we were only able to get the second block was matching

d3lt4 → {Def

then we run this code

```python
import itertools
import string
from fractions import Fraction as F

def d3lt4(msg_x1):
    if len(msg_x1) == 1:
        return ord(msg_x1)
    msg_x1 = msg_x1[::-1]
    _countdown = len(msg_x1) - 1
    vX, vY = F(ord(msg_x1[0]), _countdown).denominator, F(ord(msg_x1[0]), _countdown).numerator
    _countdown -= 1
    for idx in range(1, len(msg_x1) - 1):
        x = ord(msg_x1[idx]) + F(vX, vY)
        vY, vX = x.denominator, x.numerator
        vX, vY = vY, _countdown * vX
        _countdown -= 1
    x = ord(msg_x1[-1]) + F(vX, vY)
    vX, vY = x.denominator, x.numerator
    return (vY, vX)

def k1lo(msg_b2):
    if len(msg_b2) == 1:
        return ord(msg_b2)
    msg_b2 = msg_b2[::-1]
    pwr = (-1) ** len(msg_b2)
    f_ = F(ord(msg_b2[0]), pwr)
    a1, b2 = f_.denominator, f_.numerator
    pwr *= -1
    for idx in range(1, len(msg_b2) - 1):
        temp = ord(msg_b2[idx]) + F(a1, b2)
        b2, a1 = temp.denominator, temp.numerator
        a1, b2 = b2, pwr * a1
        pwr *= -1
    temp = ord(msg_b2[-1]) + F(a1, b2)
    a1, b2 = temp.denominator, temp.numerator
    return (b2, a1)

def zx9t(msg_c3):
    if len(msg_c3) == 1:
        return ord(msg_c3)
    msg_c3 = msg_c3[::-1]
    chaos = (-1) ** int(F(len(msg_c3), len(msg_c3)**2))
    start = F(ord(msg_c3[0]), chaos)
    l1, l2 = start.denominator, start.numerator
    chaos **= -1
    chaos = int(chaos)
    for idx in range(1, len(msg_c3) - 1):
        res = ord(msg_c3[idx]) + F(l1, l2)
        l2, l1 = res.denominator, res.numerator
        l1, l2 = l2, chaos * l1
        chaos **= -1
        chaos = int(chaos)
    final = ord(msg_c3[-1]) + F(l1, l2)
    l1, l2 = final.denominator, final.numerator
    return (l2, l1)

encrypted_tuples = [
    (29490244, 453603),
    (28735866, 233597),
    (59585246, 551617),
    (113048061, 1076555),
    (65009469, 969989)
]

fixed_segments = ["AKTH", "{Def"]
remaining_usage = {"d3lt4": 1, "k1lo": 1, "zx9t": 1}
allowed_chars = string.ascii_lowercase + string.digits + "_"
allowed_chars_seg4 = string.ascii_letters + string.digits + "{}_"
segment_length = 4
functions = [d3lt4, k1lo, zx9t]
func_names = ["d3lt4", "k1lo", "zx9t"]

def build_candidates(target, allowed_chars, segment_length, require_brace=False):
    cand = {fname: [] for fname in func_names}
    for s in itertools.product(allowed_chars, repeat=segment_length):
        seg = ''.join(s)
        if require_brace and '}' not in seg:
            continue
        for f, fname in zip(functions, func_names):
            if f(seg) == target:
                cand[fname].append(seg)
    return cand

cand_seg2 = build_candidates(encrypted_tuples[2], allowed_chars, segment_length, require_brace=False)
cand_seg3 = build_candidates(encrypted_tuples[3], allowed_chars, segment_length, require_brace=False)
cand_seg4 = build_candidates(encrypted_tuples[4], allowed_chars_seg4, segment_length, require_brace=True)

print("Candidates for seg2:")
for fname, segs in cand_seg2.items():
    print(f"  {fname}: {segs}")
print("Candidates for seg3:")
for fname, segs in cand_seg3.items():
    print(f"  {fname}: {segs}")
print("Candidates for seg4:")
for fname, segs in cand_seg4.items():
    print(f"  {fname}: {segs}")

solutions = []
for fname2, segs2 in cand_seg2.items():
    for s2 in segs2:
        for fname3, segs3 in cand_seg3.items():
            if fname3 == fname2:
                continue
            for s3 in segs3:
                for fname4, segs4 in cand_seg4.items():
                    if fname4 == fname2 or fname4 == fname3:
                        continue
                    for s4 in segs4:
                        full_flag = fixed_segments[0] + fixed_segments[1] + s2 + s3 + s4
                        solutions.append((full_flag, (fname2, fname3, fname4)))

if solutions:
    print("\nCandidate full flag(s) found:")
    for flag, assignment in solutions:
        print("Flag:", flag, "with function assignment for seg2,seg3,seg4:", assignment)
else:
    print("No full flag candidate found under current constraints.")

```

after that this code gives us this

![image.png](image%2018.png)

now we are missing the only last block

we currently have

AKTH{Defl4gging_

and I just guessed the last word :P       

which was C0de

making our flag 

```python
AKTH{Defl4gging_C0de}
```

DONT EVEN ASK ME ABOU THIS CHALLENGE I HAD AN AI FIELD DAY WITH THIS ONE