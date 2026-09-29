"""
TC-07: Legacy Cryptographic Hash Function (SHA-1).
Purpose: Tests whether a discovery tool identifies legacy SHA-1 hash usage in Python
source code, determines the operational role as MESSAGE DIGEST, and marks it as
classically broken.
"""
import hashlib

def compute_checksum(data: bytes) -> str:
    # Line 11: Direct hashlib instantiation with SHA-1 algorithm
    hasher = hashlib.sha1()
    
    # Line 14: Digest update with payload
    hasher.update(data)
    
    # Line 17: Hexadecimal digest output
    return hasher.hexdigest()
