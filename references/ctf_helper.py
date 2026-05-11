"""
CTF Helper: Common operations for CTF challenges and bug bounty hunting.
Load via exec() in execute_code or run standalone.

Usage:
    exec(open("scripts/ctf_helper.py").read())
    
    # Auto-detect challenge type
    result = analyze_challenge("file.bin")
    
    # Common crypto operations
    result = xor_bruteforce(ciphertext_bytes)
    result = decode_all_encodings("some_string")
    
    # Web testing helpers
    result = test_sqli_params("http://target/page?id=1")
    result = fuzz_headers("http://target/api")
    
    # Flag extraction
    result = extract_flags_from_file("capture.pcap")
"""

import base64
import binascii
import codecs
import hashlib
import itertools
import os
import re
import string
import subprocess
import sys
import urllib.parse
from collections import Counter
from pathlib import Path

# ============================================================
# Challenge Analysis
# ============================================================

def analyze_challenge(file_path):
    """Auto-analyze a CTF challenge file and suggest category/approach."""
    result = {"file": file_path, "category": "unknown", "suggestions": []}
    
    path = Path(file_path)
    if not path.exists():
        result["error"] = f"File not found: {file_path}"
        return result
    
    # File type detection
    try:
        file_output = subprocess.check_output(["file", str(path)], text=True).strip()
        result["file_type"] = file_output
    except:
        result["file_type"] = "unknown"
    
    # Extension-based hints
    ext = path.suffix.lower()
    ext_hints = {
        ".py": ("misc/crypto", "Look for encryption, encoding, or logic bugs"),
        ".js": ("web/misc", "Client-side JS challenge, check for hidden logic"),
        ".php": ("web", "Server-side PHP, look for injection or deserialization"),
        ".pyc": ("rev", "Python bytecode, use uncompyle6 or pycdc"),
        ".class": ("rev", "Java bytecode, use javap or jd-gui"),
        ".jar": ("rev", "Java archive, decompile with jd-gui or fernflower"),
        ".elf": ("pwn/rev", "ELF binary, check with checksec, analyze with Ghidra"),
        ".exe": ("pwn/rev", "Windows PE, analyze with Ghidra/IDA, check protections"),
        ".dll": ("rev", "Windows DLL, export analysis with Ghidra"),
        ".so": ("rev", "Shared object, analyze exports and imports"),
        ".pcap": ("forensics", "Network capture, use tshark/wireshark"),
        ".png": ("forensics", "Image, check steganography with zsteg/steghide/binwalk"),
        ".jpg": ("forensics", "Image, check EXIF data and steganography"),
        ".wav": ("forensics", "Audio, check spectrogram for hidden data"),
        ".mp3": ("forensics", "Audio, check metadata and spectrogram"),
        ".pdf": ("forensics", "Check for hidden objects, streams, metadata"),
        ".zip": ("misc/forensics", "Check password, hidden files, zip bombs"),
        ".tar": ("misc/forensics", "Extract and analyze contents"),
        ".gz": ("misc/forensics", "Decompress and analyze"),
        ".sql": ("web/misc", "SQL dump, look for credentials or structure"),
        ".log": ("forensics", "Log analysis, look for patterns or injections"),
        ".txt": ("misc", "Check encoding, steganography, hidden messages"),
        ".md": ("misc", "Check for hidden text, encoding variations"),
        ".html": ("web", "Client-side challenge, check source for hints"),
    }
    
    if ext in ext_hints:
        result["category"], result["suggestion"] = ext_hints[ext]
        result["suggestions"].append(result["suggestion"])
    
    # Binary analysis hints
    if "ELF" in result.get("file_type", ""):
        result["category"] = "pwn/rev"
        result["suggestions"].extend([
            "Run: checksec ./file",
            "Run: strings ./file | grep -i flag",
            "Run: ltrace ./file",
            "Open in Ghidra for decompilation",
            "Check for format string vulns with %x%x%x",
            "Check for buffer overflow with cyclic pattern",
        ])
    elif "PE32" in result.get("file_type", ""):
        result["category"] = "pwn/rev"
        result["suggestions"].extend([
            "Open in Ghidra/IDA for analysis",
            "Check with PEiD for packer detection",
            "Run: strings ./file | grep -i flag",
            "Check for anti-debug techniques",
        ])
    elif "Python" in result.get("file_type", "") and ext == ".pyc":
        result["category"] = "rev"
        result["suggestions"].extend([
            "Use uncompyle6 or pycdc to decompile",
            "pip install uncompyle6 && uncompyle6 file.pyc",
        ])
    
    # Strings extraction (always useful)
    try:
        strings_output = subprocess.check_output(
            ["strings", "-n", "8", str(path)], text=True, timeout=5
        )
        # Look for flag patterns
        flag_patterns = re.findall(r'(?:flag|ctf|pico|hack|key|secret|password)[{_][^}]+[}]', 
                                   strings_output, re.IGNORECASE)
        if flag_patterns:
            result["found_flags"] = flag_patterns
            result["suggestions"].append("FLAG FOUND IN STRINGS!")
        
        # Look for base64
        b64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', strings_output)
        if b64_patterns:
            result["base64_candidates"] = b64_patterns[:5]
            result["suggestions"].append(f"Found {len(b64_patterns)} base64-like strings")
        
        # Look for hex strings
        hex_patterns = re.findall(r'(?:0x)?[0-9a-fA-F]{16,}', strings_output)
        if hex_patterns:
            result["hex_candidates"] = hex_patterns[:5]
            result["suggestions"].append(f"Found {len(hex_patterns)} hex-like strings")
    except:
        pass
    
    return result


# ============================================================
# Crypto Helpers
# ============================================================

def xor_bruteforce(ciphertext):
    """Try all single-byte XOR keys on ciphertext bytes."""
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext) if all(c in string.hexdigits for c in ciphertext.replace(' ', '')) else ciphertext.encode()
    
    results = []
    for key in range(256):
        decrypted = bytes([b ^ key for b in ciphertext])
        try:
            text = decrypted.decode('ascii')
            # Score based on printable chars and common English patterns
            printable_ratio = sum(1 for c in text if c in string.printable) / len(text)
            score = printable_ratio * 100
            if 'flag' in text.lower() or 'ctf' in text.lower() or '{' in text:
                score += 50  # Bonus for flag patterns
            results.append({"key": key, "key_hex": hex(key), "text": text, "score": score})
        except:
            results.append({"key": key, "key_hex": hex(key), "text": "[non-printable]", "score": 0})
    
    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:10]  # Top 10 results


def repeating_key_xor(ciphertext, key):
    """Decrypt repeating-key XOR."""
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    if isinstance(key, str):
        key = key.encode()
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(ciphertext)])


def hamming_distance(b1, b2):
    """Calculate Hamming distance between two byte strings."""
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))


def find_xor_key_length(ciphertext, min_len=2, max_len=40):
    """Find likely key length for repeating-key XOR using normalized Hamming distance."""
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    
    distances = []
    for key_len in range(min_len, max_len + 1):
        if len(ciphertext) < key_len * 2:
            continue
        chunks = [ciphertext[i:i+key_len] for i in range(0, min(len(ciphertext), key_len * 4), key_len)]
        if len(chunks) < 2:
            continue
        avg_distance = sum(hamming_distance(chunks[i], chunks[i+1]) for i in range(len(chunks)-1)) / (len(chunks)-1)
        normalized = avg_distance / key_len
        distances.append((key_len, normalized))
    
    distances.sort(key=lambda x: x[1])
    return distances[:5]  # Top 5 likely key lengths


def crack_repeating_xor(ciphertext, max_key_len=40):
    """Full crack for repeating-key XOR."""
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    
    # Find key length
    key_lengths = find_xor_key_length(ciphertext, max_len=max_key_len)
    best_key_len = key_lengths[0][0]
    
    # Transpose: group bytes by key position
    transposed = []
    for i in range(best_key_len):
        block = bytes([ciphertext[j] for j in range(i, len(ciphertext), best_key_len)])
        transposed.append(block)
    
    # Crack each block as single-byte XOR
    key = []
    for block in transposed:
        results = xor_bruteforce(block)
        key.append(results[0]["key"])  # Best key for this position
    
    key_bytes = bytes(key)
    decrypted = repeating_key_xor(ciphertext, key_bytes)
    
    return {
        "key_length": best_key_len,
        "key": key_bytes.decode('ascii', errors='replace'),
        "key_hex": key_bytes.hex(),
        "plaintext": decrypted.decode('ascii', errors='replace'),
        "key_lengths_candidates": key_lengths[:3],
    }


def caesar_decrypt(text, shift=None):
    """Try all Caesar shifts or decrypt with specific shift."""
    if shift is not None:
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base - shift) % 26 + base))
            else:
                result.append(c)
        return {shift: ''.join(result)}
    
    # Try all shifts
    results = {}
    for s in range(26):
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base - s) % 26 + base))
            else:
                result.append(c)
        results[s] = ''.join(result)
    return results


# ============================================================
# Encoding/Decoding
# ============================================================

def decode_all_encodings(text):
    """Try decoding a string through all common encodings."""
    results = {}
    
    # Base64 variants
    for b64_func in [base64.b64decode, base64.b32decode, base64.b16decode]:
        try:
            decoded = b64_func(text.upper() if b64_func != base64.b64decode else text)
            results[b64_func.__name__] = decoded.decode('utf-8', errors='replace')
        except:
            pass
    
    # URL decode
    try:
        results["url_decode"] = urllib.parse.unquote(text)
    except:
        pass
    
    # HTML entities
    try:
        results["html_unescape"] = html.unescape(text)
    except:
        pass
    
    # Hex decode
    try:
        clean = text.replace(' ', '').replace('0x', '')
        results["hex_decode"] = bytes.fromhex(clean).decode('utf-8', errors='replace')
    except:
        pass
    
    # Rot13
    results["rot13"] = codecs.decode(text, 'rot_13')
    
    # Reverse
    results["reverse"] = text[::-1]
    
    # Binary decode
    try:
        binary_clean = text.replace(' ', '')
        results["binary_decode"] = ''.join(chr(int(binary_clean[i:i+8], 2)) for i in range(0, len(binary_clean), 8))
    except:
        pass
    
    # Look for flag patterns in results
    flag_results = {}
    for method, decoded in results.items():
        if re.search(r'(?:flag|ctf|pico|hack)[{_]', decoded, re.IGNORECASE):
            flag_results[method] = decoded
    
    return {
        "all_decodings": results,
        "flag_matches": flag_results if flag_results else "No flag patterns found",
    }


# ============================================================
# Flag Pattern Matching
# ============================================================

def extract_flags(text):
    """Extract flag patterns from any text."""
    if not isinstance(text, str):
        text = str(text)
    
    # Common CTF flag formats
    patterns = [
        r'flag\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'hackthebox\{[^}]+\}',
        r'flag-[0-9a-f]{32}',
        r'flag_[A-Za-z0-9_]+',
        r'[A-Za-z0-9+/]{20,}={0,2}',  # base64 (potential flag)
    ]
    
    found = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        if matches:
            found.extend(matches)
    
    return list(set(found))  # Deduplicate


# ============================================================
# Hash Helpers
# ============================================================

def identify_hash(hash_string):
    """Identify hash type based on length and character set."""
    h = hash_string.strip()
    length = len(h)
    
    hash_types = {
        32: "MD5 / NTLM / LM",
        40: "SHA1 / MySQL5",
        56: "SHA224",
        64: "SHA256 / SHA3-256 / RIPEMD-160",
        96: "SHA384",
        128: "SHA512 / SHA3-512",
        120: "SHA3-384",
        32: "MD5",
    }
    
    # Check character set
    if all(c in '0123456789abcdef' for c in h.lower()):
        hash_type = hash_types.get(length, f"Unknown ({length}-char hex)")
        return {"type": hash_type, "length": length, "format": "hex"}
    elif all(c in './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' for c in h):
        return {"type": "bcrypt / DES crypt", "length": length, "format": "base64-like"}
    else:
        return {"type": "Unknown", "length": length, "format": "mixed"}


def hash_bruteforce(hash_string, wordlist_path=None, hash_type="md5"):
    """Brute force a hash against a wordlist."""
    if wordlist_path is None:
        # Common wordlist locations
        candidates = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/fasttrack.txt",
            "/opt/wordlists/rockyou.txt",
        ]
        for path in candidates:
            if os.path.exists(path):
                wordlist_path = path
                break
    
    if not wordlist_path or not os.path.exists(wordlist_path):
        return {"error": f"Wordlist not found. Try: {wordlist_path}"}
    
    hash_func = getattr(hashlib, hash_type, None)
    if not hash_func:
        return {"error": f"Unknown hash type: {hash_type}. Use: md5, sha1, sha256, sha512"}
    
    target = hash_string.lower()
    
    with open(wordlist_path, 'r', errors='ignore') as f:
        for line in f:
            word = line.strip()
            if hash_func(word.encode()).hexdigest() == target:
                return {"found": True, "password": word, "hash_type": hash_type}
    
    return {"found": False, "message": f"Not found in {wordlist_path}"}


# ============================================================
# Number/Encoding Helpers
# ============================================================

def number_bases(value):
    """Show a number in all common bases."""
    if isinstance(value, str):
        # Try to parse
        if value.startswith('0x'):
            value = int(value, 16)
        elif value.startswith('0b'):
            value = int(value, 2)
        elif value.startswith('0o'):
            value = int(value, 8)
        else:
            value = int(value)
    
    return {
        "decimal": str(value),
        "hex": hex(value),
        "octal": oct(value),
        "binary": bin(value),
        "ascii": chr(value) if 32 <= value < 127 else "(non-printable)",
    }


# ============================================================
# Quick Reference
# ============================================================

def ctf_cheatsheet():
    """Print a quick reference cheatsheet."""
    return """
=== CTF QUICK REFERENCE ===

FILE ANALYSIS:
  file <target>          - File type detection
  strings <target>       - Extract printable strings
  xxd <target>           - Hex dump
  binwalk <target>       - Find embedded files
  exiftool <target>      - Metadata extraction

BINARY EXPLOITATION:
  checksec ./binary      - Check security protections
  gdb ./binary           - Debug with GDB
  ropper --file ./binary - Find ROP gadgets
  one_gadget libc.so     - Find execve gadgets

CRYPTO:
  xor bruteforce         - Try all 256 keys
  caesar cipher          - 26 shifts, try all
  rsa small e=3          - Cube root attack
  hash identify          - Length = type hint

WEB:
  sqlmap -u URL          - Automated SQL injection
  ffuf -w wordlist -u URL - Directory brute force
  nmap -sC -sV target    - Service enumeration
  whatweb URL            - Technology detection

FORENSICS:
  tshark -r capture.pcap - Analyze PCAP
  volatility -f mem.dmp  - Memory analysis
  zsteg image.png        - PNG steganography
  steghide extract -sf   - Extract hidden data

COMMON FLAG FORMATS:
  flag{...}              - Standard
  picoCTF{...}           - PicoCTF
  HTB{...}               - HackTheBox
  CTF{...}               - Generic
"""
