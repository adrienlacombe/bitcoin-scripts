#!/usr/bin/env python3
"""Independent deterministic Fast Winternitz vectors for both native hashes.

Seed: 0x42 repeated 32 times. Message: bytes(range(32)). Base 16, checksum
widths [3, 3, 4]. Prints SHA-256 digests of concatenated endpoints/signature
nodes, compared in hash_choice_tests.rs. Python stdlib only.
"""
import hashlib


def vectors(name):
    def chain_hash(data):
        digest = hashlib.sha256(data).digest()
        return hashlib.new("ripemd160", digest).digest() if name == "hash160" else digest

    message = bytes(range(32))
    namespace = chain_hash(
        f"bitcoin-lab/winternitz-{name}/v1".encode()
        + bytes([0x42]) * 32
        + len(message).to_bytes(8, "big")
    )
    digits = [d for byte in message for d in (byte >> 4, byte & 15)]
    checksum = sum(15 - d for d in digits)
    maxima = [15] * len(digits)
    for width in (3, 3, 4):
        maximum = (1 << width) - 1
        digits.append(checksum & maximum)
        checksum >>= width
        maxima.append(maximum)
    assert checksum == 0
    endpoints, signature = [], []
    for index, (digit, maximum) in enumerate(zip(digits, maxima)):
        value = chain_hash(namespace + index.to_bytes(4, "big"))
        for step in range(maximum + 1):
            if step == digit:
                signature.append(value)
            if step == maximum:
                endpoints.append(value)
            value = chain_hash(value)
    return tuple(hashlib.sha256(b"".join(nodes)).hexdigest() for nodes in (endpoints, signature))


if __name__ == "__main__":
    for hash_name in ("hash160", "sha256"):
        public_digest, signature_digest = vectors(hash_name)
        print(f"{hash_name}: public={public_digest} signature={signature_digest}")
