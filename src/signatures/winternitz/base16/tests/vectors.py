#!/usr/bin/env python3
"""Independent deterministic Fast Winternitz vectors for all native hash/commitment profiles.

Seed: 0x42 repeated 32 times. Message: bytes(range(32)). Base 16, checksum
widths [3, 3, 4]. Prints SHA-256 digests of concatenated endpoints/signature
nodes for native and 16-byte starts, compared in tests/hash_choice.rs and
src/signatures/winternitz/base16/tests/preimages.rs. Python stdlib only.
"""
import hashlib


def vectors(name, short=False):
    def chain_hash(data):
        digest = hashlib.sha256(data).digest()
        return hashlib.new("ripemd160", digest).digest() if name == "hash160" else digest

    message = bytes(range(32))
    namespace = chain_hash(
        (b"bitcoin-lab/winternitz-preimage16/v1" if short else b"")
        + f"bitcoin-lab/winternitz-{name}/v1".encode()
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
        if short:
            value = value[:16]
        for step in range(maximum + 1):
            if step == digit:
                signature.append(value)
            if step == maximum:
                endpoint = hashlib.new("ripemd160", hashlib.sha256(value).digest()).digest() if name == "sha256-hash160" else value
                endpoints.append(endpoint)
            value = chain_hash(value)
    return tuple(hashlib.sha256(b"".join(nodes)).hexdigest() for nodes in (endpoints, signature))


if __name__ == "__main__":
    for hash_name in ("hash160", "sha256", "sha256-hash160"):
        for short in (False, True):
            public_digest, signature_digest = vectors(hash_name, short)
            print(f"{hash_name}/preimage{16 if short else 'native'}: public={public_digest} signature={signature_digest}")
