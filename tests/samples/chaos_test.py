# This file tests the code_scanner's fault tolerance and regex matching

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

# Test 1: Exceptionally large key size (might test integer bounds or display limits)
rsa.generate_private_key(
    public_exponent=65537,
    key_size=99999999999999999999
)

# Test 2: Standard insecure hashing
hashlib.md5(b"test")
hashlib.sha1(b"test")

# Test 3: Hypothetical missing algorithms 
# (The scanner only looks for specific patterns, so these should be ignored)
hashlib.sha0(b"fake")
hashlib.blake3(b"fake")

# Test 4: Extremely long line with a match at the very end
long_var = "A" * 50000 + str(hashlib.sha256(b"hello").hexdigest())

# Test 5: Unicode and weird characters mixed in
# hashlib.md5 🤡
# ec.SECP384R1 😎 ¯\_(ツ)_/¯

# Test 6: Malformed patterns
# crypto.createHash('sha256'
# Cipher.getInstance("AES/CBC/PKCS5Padding") (without proper imports or syntax)
