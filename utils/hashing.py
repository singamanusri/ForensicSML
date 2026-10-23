"""SHA-256 hashing for evidence integrity checks.

A matching hash shows the file has not changed since it was hashed here.
It does NOT prove the evidence was authentic to begin with, nor does it
establish chain of custody.
"""
import hashlib


def sha256_file(path, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()
