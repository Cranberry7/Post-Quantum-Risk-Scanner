"""Sample Python file with cryptographic usage for scanner testing."""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import algorithms

# Generate an RSA key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Generate an EC key
ec_key = ec.generate_private_key(ec.SECP256R1())

# Hash some data
digest = hashlib.sha256(b"hello world").hexdigest()
old_digest = hashlib.md5(b"hello world").hexdigest()
sha1_digest = hashlib.sha1(b"hello").hexdigest()

# Symmetric cipher reference
cipher_algo = algorithms.AES(b"0" * 32)
