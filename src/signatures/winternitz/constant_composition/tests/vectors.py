#!/usr/bin/env python3
"""Independent stdlib vectors for ConstantCompositionWinternitz20.

Run this file directly. It neither imports nor parses the Rust implementation.
All ranks, codebook capacities, witness moments, and extrema use exact integer
arithmetic. The mean covers all 2**160 unchanged input messages, not a sample.
The printed script breakdown is a formula, not a Bitcoin Script execution or
consensus/policy validation. Rust tests separately check compiled-script costs.

Witness serialization includes its count and every item-length prefix. It
excludes script/transaction framing, the locking script, and terminal OP_TRUE.
All 70 items are signature data; there are zero auxiliary witness hints.
"""

from fractions import Fraction
import hashlib
import itertools
import json
from math import factorial, log2


COMPOSITION = (1,) * 15 + (2,) * 7 + (3,) * 2 + (14,)
MESSAGE_SPACE = 1 << 160
DOMAIN = b"bitcoin-lab/winternitz20-constant-composition/v1"
PREIMAGE16_DOMAIN = b"bitcoin-lab/winternitz-preimage16/v1"
SEED = b"\x42" * 32


def multinomial(counts):
    result = factorial(sum(counts))
    for count in counts:
        result //= factorial(count)
    return result


class Encoding:
    """Lexicographic ranking of distinct permutations of a fixed multiset."""

    def __init__(self, composition):
        self.composition = tuple(composition)
        if not self.composition or any(c <= 0 for c in self.composition):
            raise ValueError("every symbol must have a positive count")
        self.size = multinomial(self.composition)

    def unrank(self, rank):
        if not 0 <= rank < self.size:
            raise ValueError("rank outside codebook")
        counts = list(self.composition)
        remaining, possibilities = sum(counts), self.size
        digits = []
        while remaining:
            for digit, count in enumerate(counts):
                bucket = possibilities * count // remaining
                if rank < bucket:
                    digits.append(digit)
                    counts[digit] -= 1
                    remaining -= 1
                    possibilities = bucket
                    break
                rank -= bucket
            else:
                raise AssertionError("rank exceeds remaining permutations")
        assert rank == 0
        return digits

    def rank(self, digits):
        if len(digits) != sum(self.composition):
            raise ValueError("wrong assignment length")
        counts = list(self.composition)
        remaining, possibilities, rank = sum(counts), self.size, 0
        for digit in digits:
            if not isinstance(digit, int) or not 0 <= digit < len(counts):
                raise ValueError("digit outside alphabet")
            if not counts[digit]:
                raise ValueError("wrong composition")
            rank += possibilities * sum(counts[:digit]) // remaining
            possibilities = possibilities * counts[digit] // remaining
            counts[digit] -= 1
            remaining -= 1
        assert not any(counts)
        return rank


ENCODING = Encoding(COMPOSITION)


def encode_message(message):
    if len(message) != 20:
        raise ValueError("message must contain exactly 20 bytes")
    return ENCODING.unrank(int.from_bytes(message, "big"))


def decode_message(digits):
    rank = ENCODING.rank(digits)
    if rank >= MESSAGE_SPACE:
        raise ValueError("assignment outside the 160-bit encoder image")
    return rank.to_bytes(20, "big")


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def scriptnum(value):
    if value == 0:
        return b""
    negative, magnitude = value < 0, abs(value)
    result = bytearray()
    while magnitude:
        result.append(magnitude & 255)
        magnitude >>= 8
    if result[-1] & 128:
        result.append(128 if negative else 0)
    elif negative:
        result[-1] |= 128
    return bytes(result)


def compact_size(value):
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def serialize_witness(items):
    return compact_size(len(items)) + b"".join(
        compact_size(len(item)) + item for item in items
    )


def opening_slots(digits):
    """Yield (original key index, digit, current pool index) in witness order."""
    remaining = list(range(len(digits)))
    for digit in range(max(digits)):
        for key_index, assigned in enumerate(digits):
            if assigned == digit:
                selector = remaining.index(key_index)
                remaining.pop(selector)
                yield key_index, digit, selector


def zero_selectors(digits):
    """Independent identity: zero selectors are nonmaximum weak records."""
    maximum, largest_seen, result = max(digits), -1, 0
    for digit in digits:
        result += digit >= largest_seen and digit < maximum
        largest_seen = max(largest_seen, digit)
    return result


def exact_record_moments(encoding, limit):
    """Return sum, minimum, maximum zero-selector counts for ranks [0, limit).

    For an unrestricted suffix, each of its c_d copies of symbol d precedes
    all higher symbols with probability 1/(1 + number of higher symbols).
    Previous higher symbols exclude d; equal previous symbols do not. A
    lexicographic prefix splits into complete buckets plus one partial bucket.
    """
    if not 0 < limit <= encoding.size:
        raise ValueError("invalid prefix size")
    maximum = len(encoding.composition) - 1

    def prefix(counts, possibilities, bound, largest_seen):
        if bound == possibilities:
            mean = sum((
                Fraction(counts[d], 1 + sum(counts[d + 1:]))
                for d in range(max(0, largest_seen), maximum)
            ), Fraction())
            total = mean * possibilities
            assert total.denominator == 1
            # Either a maximum remains and can be put first, or it was seen.
            minimum = 0
            most = sum(counts[max(0, largest_seen):maximum])
            return total.numerator, minimum, most
        remaining = sum(counts)
        total, least, most = 0, remaining + 1, 0
        for digit, count in enumerate(counts):
            bucket = possibilities * count // remaining
            take = min(bound, bucket)
            if take:
                suffix = list(counts)
                suffix[digit] -= 1
                subtotal, submin, submax = prefix(
                    suffix, bucket, take, max(largest_seen, digit)
                )
                record = int(digit >= largest_seen and digit < maximum)
                total += subtotal + take * record
                least = min(least, submin + record)
                most = max(most, submax + record)
                bound -= take
            if not bound:
                break
        assert bound == 0
        return total, least, most

    return prefix(encoding.composition, encoding.size, limit, -1)


def exact_witness_moments(native_bytes, start_bytes):
    total_records, min_records, max_records = exact_record_moments(
        ENCODING, MESSAGE_SPACE
    )
    openings = sum(COMPOSITION[:-1])
    assert sum(COMPOSITION) < 128 and 2 * openings < 253
    # Each nonzero selector costs two bytes including framing; zero costs one.
    bound = 1 + openings * (native_bytes + 3)
    bound -= COMPOSITION[0] * (native_bytes - start_bytes)
    mean = Fraction(bound * MESSAGE_SPACE - total_records, MESSAGE_SPACE)
    return {
        "minimum_bytes": bound - max_records,
        "maximum_bytes": bound - min_records,
        "mean_bytes": float(mean),
        "mean_numerator": str(mean.numerator),
        "mean_denominator": str(mean.denominator),
    }


def script_formula(profile):
    """Generator cost formula; independently compiled bytecode is authoritative."""
    maximum, chains = len(COMPOSITION) - 1, sum(COMPOSITION)
    openings, implicit = sum(COMPOSITION[:-1]), COMPOSITION[-1]
    commitment_bytes = 32 if profile == "sha256" else 20
    key_pushes = (commitment_bytes + 1) * chains
    hashes = sum(
        count * ((maximum - digit) if profile == "hash160"
                 else (maximum - digit + 1) // 2)
        for digit, count in enumerate(COMPOSITION[:-1])
    )
    commit_ops = openings if profile == "sha256_hash160" else 0
    routing = sum(
        (1 if remaining - 1 <= 16 else 2) + 7
        for remaining in range(implicit + 1, chains + 1)
    )
    cleanup = (implicit + 1) // 2
    return {
        "public_key_pushes": key_pushes,
        "chain_hash_opcodes": hashes,
        "endpoint_commitment_opcodes": commit_ops,
        "staging_routing_and_comparisons": routing,
        "cleanup": cleanup,
        "total_script_bytes_estimate": key_pushes + hashes + commit_ops + routing + cleanup,
    }


def vectors(profile, shortened, fixtures):
    native_hash = hash160 if profile == "hash160" else lambda x: hashlib.sha256(x).digest()
    commitment = hash160 if profile == "sha256_hash160" else lambda x: x
    hash_domain = {
        "hash160": b"bitcoin-lab/winternitz-hash160/v1",
        "sha256": b"bitcoin-lab/winternitz-sha256/v1",
        "sha256_hash160": b"bitcoin-lab/winternitz-sha256-hash160/v1",
    }[profile]
    native_bytes = 20 if profile == "hash160" else 32
    start_bytes = 16 if shortened else native_bytes
    namespace = native_hash(
        DOMAIN + hash_domain + (PREIMAGE16_DOMAIN if shortened else b"")
        + bytes(COMPOSITION) + SEED
    )
    chains = []
    for i in range(sum(COMPOSITION)):
        start = native_hash(namespace + i.to_bytes(4, "big"))[:start_bytes]
        nodes = [start]
        for _ in COMPOSITION[1:]:
            nodes.append(native_hash(nodes[-1]))
        chains.append(nodes)
    endpoints = [commitment(nodes[-1]) for nodes in chains]
    moments = exact_witness_moments(native_bytes, start_bytes)
    results = []
    for name, message in fixtures.items():
        digits = encode_message(message)
        assert decode_message(digits) == message
        nodes = [chain[digit] for chain, digit in zip(chains, digits)]
        slots = list(opening_slots(digits))
        items = []
        for key, digit, selector in slots:
            items.extend((scriptnum(selector), nodes[key]))
            candidate = nodes[key]
            for _ in range(len(COMPOSITION) - 1 - digit):
                candidate = native_hash(candidate)
            assert commitment(candidate) == endpoints[key]
        assert len(items) == 70
        assert sum(selector == 0 for _, _, selector in slots) == zero_selectors(digits)
        serialized = serialize_witness(items)
        assert len(serialized) == moments["maximum_bytes"] - zero_selectors(digits)
        results.append({
            "name": name,
            "message_hex": message.hex(),
            "digits_hex": bytes(digits).hex(),
            "selectors": [selector for _, _, selector in slots],
            "zero_selectors": zero_selectors(digits),
            "first_node_hex": nodes[0].hex(),
            "nodes_sha256": hashlib.sha256(b"".join(nodes)).hexdigest(),
            "serialized_witness_bytes": len(serialized),
            "serialized_witness_sha256": hashlib.sha256(serialized).hexdigest(),
        })
    return {
        "native_hash_bytes": native_bytes,
        "start_bytes": start_bytes,
        "namespace_hex": namespace.hex(),
        "first_endpoint_hex": endpoints[0].hex(),
        "last_endpoint_hex": endpoints[-1].hex(),
        "endpoints_sha256": hashlib.sha256(b"".join(endpoints)).hexdigest(),
        "formula_script_cost": script_formula(profile),
        "exact_witness_moments": moments,
        "fixtures": results,
    }


def expect_rejection(function, value):
    try:
        function(value)
    except ValueError:
        return
    raise AssertionError("malformed input was accepted")


def self_check():
    # Exhaustive independent toy enumeration checks rank/unrank and every prefix
    # of the exact record-moment recurrence against actual pool selectors.
    toy = Encoding((2, 1, 2))
    permutations = sorted(set(itertools.permutations((0, 0, 1, 2, 2))))
    assert len(permutations) == toy.size
    records = []
    for rank, digits in enumerate(permutations):
        assert tuple(toy.unrank(rank)) == digits and toy.rank(digits) == rank
        count = sum(index == 0 for _, _, index in opening_slots(digits))
        assert count == zero_selectors(digits)
        toy_items = []
        for _, digit, selector in opening_slots(digits):
            toy_items.extend((scriptnum(selector), bytes(16 if digit == 0 else 20)))
        assert len(serialize_witness(toy_items)) == 1 + 23 * 3 - 4 * 2 - count
        records.append(count)
        assert exact_record_moments(toy, rank + 1) == (
            sum(records), min(records), max(records)
        )
    assert ENCODING.size == 1514202802528191317310959056853549737574400000000
    assert ENCODING.size >= MESSAGE_SPACE
    for i in range(256):
        message = hashlib.sha256(i.to_bytes(4, "big")).digest()[:20]
        assert decode_message(encode_message(message)) == message
    for rank in (0, MESSAGE_SPACE - 1, MESSAGE_SPACE, ENCODING.size - 1):
        assert ENCODING.rank(ENCODING.unrank(rank)) == rank
    expect_rejection(ENCODING.unrank, -1)
    expect_rejection(ENCODING.unrank, ENCODING.size)
    expect_rejection(encode_message, bytes(19))
    expect_rejection(encode_message, bytes(21))
    expect_rejection(decode_message, ENCODING.unrank(MESSAGE_SPACE))
    expect_rejection(decode_message, ENCODING.unrank(ENCODING.size - 1))
    invalid = ENCODING.unrank(0)
    expect_rejection(decode_message, invalid[:-1])
    invalid[0] = invalid[1]
    expect_rejection(decode_message, invalid)
    invalid[0] = len(COMPOSITION)
    expect_rejection(decode_message, invalid)
    # The first leading-maximum assignment is within the encoder image and
    # attains the all-nonzero-selector bound without message grinding.
    first_maximum_rank = ENCODING.size * sum(COMPOSITION[:-1]) // sum(COMPOSITION)
    assert first_maximum_rank < MESSAGE_SPACE
    maximum_message = first_maximum_rank.to_bytes(20, "big")
    assert maximum_message.hex() == "bd736e13851a9581860e655a5f31f6d5e4000000"
    assert zero_selectors(encode_message(maximum_message)) == 0
    moments = exact_witness_moments(20, 16)
    assert (moments["minimum_bytes"], moments["maximum_bytes"]) == (767, 802)
    return maximum_message


def main():
    maximum_message = self_check()
    fixtures = {
        "zero": bytes(20),
        "ff": b"\xff" * 20,
        "varied_37i": bytes(37 * i % 256 for i in range(20)),
        "range": bytes(range(20)),
        "maximum_witness": maximum_message,
    }
    profiles = {
        profile + ("_preimage16" if shortened else "_native"): vectors(
            profile, shortened, fixtures
        )
        for profile in ("hash160", "sha256", "sha256_hash160")
        for shortened in (True, False)
    }
    print(json.dumps({
        "self_checks": "passed",
        "composition": COMPOSITION,
        "codeword_count": str(ENCODING.size),
        "approx_log2_codeword_count": log2(ENCODING.size),
        "message_count": str(MESSAGE_SPACE),
        "witness_data_items": 70,
        "auxiliary_hint_items": 0,
        "seed_hex": SEED.hex(),
        "profiles": profiles,
    }, indent=2))


if __name__ == "__main__":
    main()
