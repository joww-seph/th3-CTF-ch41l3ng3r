# CTF General Skills - Complete Cheatsheet & Workflow Guide

## Table of Contents
1. [Command Line & File Management](#command-line--file-management)
2. [Git Operations](#git-operations)
3. [Programming Languages](#programming-languages)
4. [Data Encoding & Conversion](#data-encoding--conversion)
5. [Binary Operations](#binary-operations)
6. [Hashing & Cryptography](#hashing--cryptography)
7. [Networking Basics](#networking-basics)
8. [Web Exploitation](#web-exploitation)
9. [Forensics & Steganography](#forensics--steganography)
10. [Regular Expressions](#regular-expressions)
11. [Automation Scripts](#automation-scripts)
12. [CTF Workflow](#ctf-workflow)
13. [Tools & Resources](#tools--resources)

---

## Command Line & File Management

### Essential Commands

#### Navigation & File Operations
```bash
# Directory navigation
cd /path/to/dir       # change directory
cd ..                 # up one level
pwd                   # current directory

# List files
ls -la                # detailed list with hidden files
ls -lh                # human-readable sizes

# File operations
cat file.txt          # view file
head -n 20 file.txt   # first 20 lines
tail -n 20 file.txt   # last 20 lines
less file.txt         # page through file

# File information
file filename         # identify file type
wc -l file.txt        # count lines
```

#### Searching for Flags
```bash
# Basic search
grep "flag" file.txt
grep -r "flag" .                    # recursive
grep -rni "picoCTF" .               # case-insensitive with line numbers

# Find files
find . -name "*flag*"
find . -type f -name "*.txt"

# Search in binary files
strings binary_file | grep flag
strings -n 8 file                   # strings 8+ chars

# Extract from hex
xxd file | grep flag
hexdump -C file | grep flag

# Combine parts
grep "part" logs.txt | cut -d: -f2 | tr -d '\n'
```

#### Text Processing
```bash
# Cut and sort
cut -d':' -f1 file.txt              # cut by delimiter
sort file.txt | uniq                # sort and remove duplicates

# Transform
tr 'a-z' 'A-Z' < file.txt          # lowercase to uppercase
tr -d ' ' < file.txt               # delete spaces

# AWK
awk '{print $1}' file.txt          # first column
awk -F':' '{print $1}' file.txt    # custom delimiter

# Piping
cat file.txt | grep pattern | wc -l
find . -name "*.txt" | xargs grep flag
```

#### Archives
```bash
# Tar
tar -xvf archive.tar               # extract
tar -czvf archive.tar.gz files/    # compress

# Zip
unzip archive.zip
unzip -l archive.zip               # list contents
```

---

## Git Operations

### Basic Git Commands
```bash
# Status and log
git status
git log
git log --oneline
git log --graph --all

# View specific commit
git show <commit-hash>
git show HEAD~1                    # previous commit
```

### Finding Flags in Git

#### Search All Commits
```bash
# Search for string in all commits
git log -S "flag" --all
git grep "flag" $(git rev-list --all)

# View file at specific commit
git show <commit>:filename
```

#### Navigate Commits
```bash
# Checkout old commits
git checkout <commit-hash>
git checkout HEAD~5                # 5 commits back

# List all branches
git branch -a

# View file from branch
git show branch1:flag.txt
```

#### Merge Strategy for CTF
```bash
# Method 1: Checkout and view each branch
for branch in $(git branch -a | grep part); do
    echo "=== $branch ==="
    git show $branch:flag.txt
done

# Method 2: Sequential merge
git checkout <init-commit>
git merge part1
cat flag.txt > part1.txt

git checkout <init-commit>
git merge part2
cat flag.txt > part2.txt

# Combine all parts
cat part*.txt > complete_flag.txt
```

#### Advanced Git
```bash
# Search in file history
git log -p filename                # show changes
git log --follow filename          # follow renames

# Stashes
git stash list
git stash show -p stash@{0}

# Reflog (all reference changes)
git reflog
git show HEAD@{5}
```

---

## Programming Languages

### Python for CTF

#### Basic Syntax
```python
# Variables
x = 42
name = "CTF"
flag = ""

# Lists
items = [1, 2, 3]
items.append(4)
items[0]                          # first element

# Dictionaries
data = {"key": "value"}
data["key"]

# Loops
for i in range(10):
    print(i)

for item in items:
    print(item)

# Functions
def decode(text):
    return text[::-1]
```

#### File Operations
```python
# Read file
with open('file.txt', 'r') as f:
    content = f.read()
    lines = f.readlines()

# Write file
with open('output.txt', 'w') as f:
    f.write("text")

# Binary files
with open('file.bin', 'rb') as f:
    data = f.read()
```

#### String Manipulation
```python
s = "Hello World"
s.lower()                         # "hello world"
s.upper()                         # "HELLO WORLD"
s.replace("World", "CTF")         # "Hello CTF"
s.split()                         # ["Hello", "World"]
s[::-1]                           # reverse string

# Join
"-".join(["a", "b", "c"])        # "a-b-c"
```

#### Bytes and Encoding
```python
# String to bytes
text = "Hello"
b = text.encode('utf-8')

# Bytes to string
text = b.decode('utf-8')

# Hex
b.hex()                           # '48656c6c6f'
bytes.fromhex('48656c6c6f')      # b'Hello'

# ASCII conversion
ord('A')                          # 65
chr(65)                           # 'A'

# List to string
chars = [72, 101, 108, 108, 111]
''.join([chr(c) for c in chars]) # "Hello"
```

#### Useful Libraries
```python
import base64
import hashlib
import requests
import re

# Base64
base64.b64encode(b"Hello")
base64.b64decode(b"SGVsbG8=")

# Hashing
hashlib.md5(b"text").hexdigest()
hashlib.sha256(b"text").hexdigest()

# HTTP requests
r = requests.get('https://example.com')
r.text
r.json()

# Regular expressions
re.findall(r'flag\{[^}]+\}', text)
```

### Bash Scripting

#### Variables and Loops
```bash
#!/bin/bash

# Variables
name="value"
flag=""

# For loop
for i in {1..10}; do
    echo $i
done

for file in *.txt; do
    cat "$file"
done

# While loop
while [ $counter -lt 10 ]; do
    ((counter++))
done

# If statement
if [ -f "file.txt" ]; then
    cat file.txt
fi

# Functions
greet() {
    echo "Hello $1"
}
greet "World"
```

#### CTF Bash Scripts
```bash
# Flag hunter
for file in *; do
    strings "$file" | grep -i flag
done

# Combine parts
for i in {1..5}; do
    cat part${i}.txt >> complete_flag.txt
done
```

### Rust for CTF

#### Common Issues
```rust
// ❌ Immutable string
let s = String::from("hello");
s.push_str(" world");  // Error!

// ✅ Fixed: Add mut
let mut s = String::from("hello");
s.push_str(" world");

// ❌ Wrong return (semicolon)
fn add(a: i32, b: i32) -> i32 {
    a + b;  // Wrong!
}

// ✅ Fixed: Remove semicolon or use return
fn add(a: i32, b: i32) -> i32 {
    a + b   // Correct
}

// ✅ Or explicit return
fn add(a: i32, b: i32) -> i32 {
    return a + b;  // Also correct
}

// Print formatting
println!("Value: {}", x);
println!("x: {}, y: {}", x, y);
```

#### Running Rust
```bash
cargo run                         # build and run
cargo check                       # check for errors
cargo build --release             # optimized build
```

---

## Data Encoding & Conversion

### Number Base Conversions

#### Python
```python
# Decimal to other bases
hex(255)           # '0xff'
bin(255)           # '0b11111111'
oct(255)           # '0o377'

# To decimal
int('ff', 16)      # 255 (hex)
int('11111111', 2) # 255 (binary)
int('377', 8)      # 255 (octal)

# Format without prefix
format(255, 'x')   # 'ff'
format(255, 'b')   # '11111111'
```

#### Bash
```bash
# Decimal to hex
printf '%x\n' 255

# Hex to decimal
printf '%d\n' 0xff

# Using bc
echo "obase=16; 255" | bc         # hex
echo "ibase=16; FF" | bc          # to decimal
```

### String Encodings

#### Hex and Strings
```python
# String to hex
"Hello".encode().hex()            # '48656c6c6f'

# Hex to string
bytes.fromhex('48656c6c6f').decode()  # 'Hello'
```

```bash
# Bash hex conversion
echo -n "Hello" | xxd -p          # to hex
echo "48656c6c6f" | xxd -r -p     # from hex
```

#### Base64
```python
import base64

# Encode
base64.b64encode(b"Hello")        # b'SGVsbG8='

# Decode
base64.b64decode(b'SGVsbG8=')     # b'Hello'
```

```bash
# Bash base64
echo -n "Hello" | base64          # encode
echo "SGVsbG8=" | base64 -d       # decode
```

#### URL Encoding
```python
from urllib.parse import quote, unquote

quote("hello world")              # 'hello%20world'
unquote("hello%20world")          # 'hello world'
```

### Decimal to Text
```python
# Decimal array to string
decimals = [72, 101, 108, 108, 111]
''.join([chr(d) for d in decimals])  # "Hello"

# From string with spaces
text = "72 101 108 108 111"
''.join([chr(int(x)) for x in text.split()])
```

```bash
# Bash method
echo "72 101 108 108 111" | awk '{for(i=1;i<=NF;i++)printf("%c",$i)}'
```

### Endianness

#### Little vs Big Endian
```python
# Little Endian: Least significant byte first
# Big Endian: Most significant byte first

num = 0x12345678

# To bytes
little = num.to_bytes(4, 'little')  # b'xV4\x12'
big = num.to_bytes(4, 'big')        # b'\x124Vx'

# From bytes
int.from_bytes(b'xV4\x12', 'little')
int.from_bytes(b'\x124Vx', 'big')

# Using struct
import struct
struct.pack('<I', num)    # little endian
struct.pack('>I', num)    # big endian
```

---

## Binary Operations

### Bitwise Operations
```python
# AND, OR, XOR, NOT
12 & 10            # 8   (AND)
12 | 10            # 14  (OR)
12 ^ 10            # 6   (XOR)
~12                # -13 (NOT)

# Shift
3 << 2             # 12  (left shift = multiply by 4)
12 >> 2            # 3   (right shift = divide by 4)
```

### Bit Manipulation
```python
# Get bit at position
def get_bit(num, pos):
    return (num >> pos) & 1

# Set bit
def set_bit(num, pos):
    return num | (1 << pos)

# Clear bit
def clear_bit(num, pos):
    return num & ~(1 << pos)

# Toggle bit
def toggle_bit(num, pos):
    return num ^ (1 << pos)
```

### XOR Cipher

#### Understanding XOR
```
Properties:
- A ^ A = 0
- A ^ 0 = A
- A ^ B ^ B = A (self-inverse)
```

#### Implementation
```python
# Single-byte XOR
def xor_single(data, key):
    if isinstance(data, str):
        data = data.encode()
    return bytes([b ^ key for b in data])

# Multi-byte XOR (repeating key)
def xor_multi(data, key):
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    return bytes([data[i] ^ key[i % len(key)] 
                  for i in range(len(data))])

# Brute force single-byte XOR
def brute_xor(ciphertext):
    for key in range(256):
        try:
            plaintext = xor_single(ciphertext, key)
            text = plaintext.decode('ascii')
            if 'flag' in text.lower():
                print(f"Key {key}: {text}")
        except:
            pass
```

---

## Hashing & Cryptography

### Common Hash Algorithms

#### Python
```python
import hashlib

text = "password"

# MD5 (32 hex chars)
hashlib.md5(text.encode()).hexdigest()

# SHA-1 (40 hex chars)
hashlib.sha1(text.encode()).hexdigest()

# SHA-256 (64 hex chars)
hashlib.sha256(text.encode()).hexdigest()

# SHA-512 (128 hex chars)
hashlib.sha512(text.encode()).hexdigest()
```

#### Bash
```bash
echo -n "password" | md5sum
echo -n "password" | sha1sum
echo -n "password" | sha256sum
echo -n "password" | sha512sum
```

### Hash Identification
```python
def identify_hash(hash_str):
    lengths = {
        32: 'MD5',
        40: 'SHA-1',
        64: 'SHA-256',
        128: 'SHA-512'
    }
    return lengths.get(len(hash_str), 'Unknown')
```

### Hash Cracking Tools

**Online:**
- CrackStation: https://crackstation.net/
- Hashes.com: https://hashes.com/en/decrypt/hash

**Offline:**
```bash
# Hashcat (GPU-based)
hashcat -m 0 hash.txt wordlist.txt     # MD5
hashcat -m 100 hash.txt wordlist.txt   # SHA1
hashcat -m 1400 hash.txt wordlist.txt  # SHA256

# John the Ripper (CPU-based)
john --format=raw-md5 --wordlist=rockyou.txt hash.txt
john --show hash.txt
```

---

## Networking Basics

### TCP/IP Fundamentals
```bash
# Connect to server
nc example.com 1234                # netcat
telnet example.com 1234            # telnet

# Listen on port
nc -lvp 1234                       # listen

# Send/receive data
echo "data" | nc example.com 1234

# HTTP request
nc example.com 80
GET / HTTP/1.1
Host: example.com
```

### Network Analysis
```bash
# Analyze pcap files
wireshark capture.pcap             # GUI
tshark -r capture.pcap             # CLI

# Follow TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0

# Filter packets
tshark -r capture.pcap -Y "http"
```

### Python Socket
```python
import socket

# Connect
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('example.com', 1234))
s.send(b'Hello\n')
data = s.recv(4096)
s.close()
```

---

## Web Exploitation

### Basic Techniques

#### View Source Code
```bash
# Download page
curl https://example.com
wget https://example.com

# View headers
curl -I https://example.com
curl -v https://example.com
```

#### Common Files to Check
```bash
/robots.txt                        # disallowed paths
/sitemap.xml                       # site structure
/.git/                             # exposed git repo
/admin/                            # admin panel
/backup/                           # backup files
```

#### Browser Developer Tools
- View Page Source (Ctrl+U)
- Inspect Element (F12)
- Network tab (see requests)
- Console (run JavaScript)
- Storage (cookies, local storage)

#### Python Requests
```python
import requests

# GET
r = requests.get('https://example.com')
print(r.text)
print(r.headers)

# POST
data = {'username': 'admin', 'password': 'pass'}
r = requests.post('https://example.com/login', data=data)

# Cookies
cookies = {'session': 'abc123'}
r = requests.get('https://example.com', cookies=cookies)

# Custom headers
headers = {'User-Agent': 'MyBot'}
r = requests.get('https://example.com', headers=headers)
```

---

## Forensics & Steganography

### File Analysis
```bash
# Identify file type
file image.jpg

# Metadata
exiftool image.jpg                 # detailed metadata
strings image.jpg                  # readable strings

# Hex dump
xxd image.jpg | less
hexdump -C image.jpg | less

# Find embedded files
binwalk image.jpg
binwalk -e image.jpg               # extract

# File carving
foremost image.jpg
```

### Steganography Tools
```bash
# Steghide (JPEG/BMP/WAV)
steghide extract -sf image.jpg
steghide info image.jpg

# LSB steganography
zsteg image.png                    # PNG/BMP

# Stegsolve (GUI tool)
# Download: http://www.caesum.com/handbook/Stegsolve.jar
java -jar stegsolve.jar
```

### Image Analysis
- **Stegsolve**: Analyze image planes, filters
- Check LSB (Least Significant Bit)
- Try different color channels (R, G, B, A)
- Look for hidden images in alpha channel

---

## Regular Expressions

### Common Patterns
```python
import re

# Find flags
re.findall(r'flag\{[^}]+\}', text)
re.findall(r'picoCTF\{[^}]+\}', text)

# Hex strings
re.findall(r'[0-9a-fA-F]{32,}', text)

# Base64-like strings
re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)

# Email addresses
re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)

# URLs
re.findall(r'https?://[^\s]+', text)

# IP addresses
re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
```

### Regex in Bash
```bash
grep -E "pattern" file.txt
grep -oE "flag\{[^}]+\}" file.txt  # only matching part
```

---

## Automation Scripts

### 1. Flag Part Combiner
```python
#!/usr/bin/env python3
import os
import re

def combine_flags(directory="."):
    parts = {}
    pattern = re.compile(r'part[_-]?(\d+):?\s*(.+)', re.I)
    
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                    for num, part in pattern.findall(content):
                        parts[int(num)] = part.strip()
            except:
                pass
    
    return ''.join([parts[i] for i in sorted(parts.keys())])

print(combine_flags())
```

### 2. Multi-Format Decoder
```python
#!/usr/bin/env python3
import base64
import sys

def decode_all(data):
    print(f"Input: {data}\n")
    
    # Hex
    try:
        result = bytes.fromhex(data).decode('ascii')
        print(f"Hex: {result}")
    except:
        pass
    
    # Base64
    try:
        result = base64.b64decode(data).decode('ascii')
        print(f"Base64: {result}")
    except:
        pass
    
    # Decimal
    try:
        if ' ' in data:
            result = ''.join([chr(int(x)) for x in data.split()])
            print(f"Decimal: {result}")
    except:
        pass
    
    # Binary
    try:
        if all(c in '01 ' for c in data):
            result = ''.join([chr(int(b, 2)) for b in data.split()])
            print(f"Binary: {result}")
    except:
        pass

data = sys.argv[1] if len(sys.argv) > 1 else input("Enter data: ")
decode_all(data)
```

### 3. Git Flag Hunter
```python
#!/usr/bin/env python3
import subprocess

def search_git(pattern="flag"):
    try:
        result = subprocess.run(
            ['git', 'rev-list', '--all'],
            capture_output=True,
            text=True
        )
        commits = result.stdout.strip().split('\n')
        
        for commit in commits:
            result = subprocess.run(
                ['git', 'grep', pattern, commit],
                capture_output=True,
                text=True
            )
            if result.stdout:
                print(f"\n=== Commit {commit[:7]} ===")
                print(result.stdout)
    except Exception as e:
        print(f"Error: {e}")

search_git()
```

### 4. XOR Brute Force
```python
#!/usr/bin/env python3
import sys

def xor_brute(hex_string):
    data = bytes.fromhex(hex_string)
    
    for key in range(256):
        result = bytes([b ^ key for b in data])
        try:
            text = result.decode('ascii')
            if text.isprintable() and any(c.isalpha() for c in text):
                print(f"Key {key:3d} (0x{key:02x}): {text}")
        except:
            pass

if len(sys.argv) > 1:
    xor_brute(sys.argv[1])
else:
    print("Usage: python xor_brute.py <hex_string>")
```

### 5. Hash Generator
```python
#!/usr/bin/env python3
import hashlib
import sys

def generate_hashes(text):
    print(f"Text: {text}\n")
    print(f"MD5:    {hashlib.md5(text.encode()).hexdigest()}")
    print(f"SHA1:   {hashlib.sha1(text.encode()).hexdigest()}")
    print(f"SHA256: {hashlib.sha256(text.encode()).hexdigest()}")
    print(f"SHA512: {hashlib.sha512(text.encode()).hexdigest()}")

text = sys.argv[1] if len(sys.argv) > 1 else input("Enter text: ")
generate_hashes(text)
```

### 6. Nested Decoder
```python
#!/usr/bin/env python3
import base64

def nested_decode(data, max_depth=10):
    print(f"Level 0: {data}")
    current = data
    
    for depth in range(max_depth):
        decoded = False
        
        # Try Base64
        try:
            result = base64.b64decode(current).decode('ascii')
            if result != current and result.isprintable():
                current = result
                print(f"Level {depth+1} (Base64): {current}")
                decoded = True
        except:
            pass
        
        # Try Hex
        if not decoded:
            try:
                result = bytes.fromhex(current).decode('ascii')
                if result != current and result.isprintable():
                    current = result
                    print(f"Level {depth+1} (Hex): {current}")
                    decoded = True
            except:
                pass
        
        if not decoded:
            break
    
    return current

import sys
data = sys.argv[1] if len(sys.argv) > 1 else input("Enter data: ")
nested_decode(data)
```

---

## CTF Workflow

### Step-by-Step Approach

1. **Read Challenge Carefully**
   - Follow instructions literally
   - Note all hints and keywords
   - Check for attachments

2. **Identify File Types**
```bash
file *
strings * | grep flag
```

3. **Check Source Code First**
   - Always read before running
   - Look for hardcoded flags
   - Understand the logic

4. **Try Simple Solutions First**
   - Use Ctrl+F to search
   - Check obvious locations
   - Test basic encodings

5. **Use Tools Systematically**
   - CyberChef for encoding chains
   - Python for automation
   - Bash for file processing

6. **Document Everything**
   - Keep notes of attempts
   - Save intermediate results
   - Track patterns

### Common Patterns

- Flags scattered in multiple files
- Nested encodings (base64 → hex → rot13)
- Hidden in git history
- Encoded in various bases
- XOR encrypted
- Hidden in binary files
- Steganography in images
- Network traffic analysis

---

## Tools & Resources

### Essential Tools

#### Command Line Tools
- `grep`, `awk`, `sed` - text processing
- `xxd`, `hexdump` - hex viewing
- `strings` - extract strings
- `file` - identify types
- `base64` - encoding/decoding
- `nc` (netcat) - networking

#### Python Libraries
```bash
pip install pwntools
pip install requests
pip install pycryptodome
```

#### Online Tools
- **CyberChef**: https://gchq.github.io/CyberChef/
- **CrackStation**: https://crackstation.net/
- **dCode**: https://www.dcode.fr/
- **Regex101**: https://regex101.com/
- **Base64 Decode**: https://www.base64decode.org/

#### Downloadable Tools
- **Wireshark**: https://www.wireshark.org/
- **Binwalk**: https://github.com/ReFirmLabs/binwalk
- **Steghide**: http://steghide.sourceforge.net/
- **Stegsolve**: http://www.caesum.com/handbook/Stegsolve.jar
- **ExifTool**: https://exiftool.org/
- **Hashcat**: https://hashcat.net/hashcat/
- **John the Ripper**: https://www.openwall.com/john/

### Learning Resources
- **picoCTF**: https://picoctf.org/
- **OverTheWire**: https://overthewire.org/
- **CTFtime**: https://ctftime.org/
- **HackTheBox**: https://www.hackthebox.com/

### Quick Reference

#### File Magic Bytes
```
PNG:  89 50 4E 47
JPEG: FF D8 FF
GIF:  47 49 46 38
ZIP:  50 4B 03 04
PDF:  25 50 44 46
```

#### Flag Formats
```
picoCTF{...}
flag{...}
FLAG{...}
CTF{...}
```

---

## Tips and Tricks

### For Beginners
1. Always check source code before running
2. Use Ctrl+F liberally
3. Try the simplest solution first
4. Learn to read hex dumps
5. Master basic command-line tools

### For Advanced Users
1. Automate repetitive tasks
2. Build a personal toolkit
3. Learn to chain tools together
4. Practice speed and efficiency
5. Study past CTF writeups

### Common Mistakes to Avoid
1. Not reading instructions fully
2. Overcomplicating solutions
3. Ignoring error messages
4. Forgetting to check file types
5. Not documenting your work

### When Stuck
1. Take a break
2. Re-read the challenge
3. Try a different approach
4. Search for similar problems
5. Use hints if available

---

## Automation Opportunities

Tasks that can be automated:
- ✅ Combining scattered flag parts
- ✅ Multi-format decoding
- ✅ Git history searching
- ✅ Binary operations (XOR, shifts)
- ✅ Hash generation/identification
- ✅ Nested decoding
- ✅ Batch file analysis
- ✅ String extraction from binaries

All scripts provided are ready to use!