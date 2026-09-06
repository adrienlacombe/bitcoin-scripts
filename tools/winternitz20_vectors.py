#!/usr/bin/env python3
"""Independent stdlib vectors and exact costs for ConstantSumWinternitz20.

The unchanged 20-byte message is its big-endian lexicographic rank in the
fixed-sum code. Digit 0 is selected first using suffix counts. This script
does not import, execute, or parse the Rust implementation. Constants and
domain separation are intentionally duplicated for differential checks.

Mean and maximum serialized witness sizes are exact over the first 2**160
codewords, not sampled estimates. They include witness count/item framing,
but exclude locking scripts and transaction overhead. An independent sum DP
also computes the ordinary 20-byte base-16 numeric baseline over all 2**160
messages. The fixed-sum method is established research:
https://eprint.iacr.org/2023/850.pdf.
"""

from fractions import Fraction
from functools import lru_cache
import hashlib
import itertools
import json


RADICES = (16,) * 32 + (18,) * 4 + (20,) * 5
DIGIT_SUM = 321
MESSAGE_SPACE = 1 << 160
DOMAIN = b"bitcoin-lab/winternitz20-constant-sum/v1"
PREIMAGE16_DOMAIN = b"bitcoin-lab/winternitz-preimage16/v1"
SEED = b"\x42" * 32


class Encoding:
    """Exact suffix-count ranking of bounded vectors with a fixed sum."""

    def __init__(self, radices, digit_sum):
        self.radices = tuple(radices)
        self.digit_sum = digit_sum
        n = len(self.radices)
        self.counts = [[0] * (digit_sum + 1) for _ in range(n + 1)]
        self.counts[n][0] = 1
        for i in range(n - 1, -1, -1):
            for remaining in range(digit_sum + 1):
                self.counts[i][remaining] = sum(
                    self.counts[i + 1][remaining - digit]
                    for digit in range(min(self.radices[i], remaining + 1))
                )

    @property
    def size(self):
        return self.counts[0][self.digit_sum]

    def unrank(self, rank):
        if not 0 <= rank < self.size:
            raise ValueError("rank is outside the fixed-sum code")
        remaining = self.digit_sum
        digits = []
        for i, radix in enumerate(self.radices):
            for digit in range(min(radix, remaining + 1)):
                bucket = self.counts[i + 1][remaining - digit]
                if rank < bucket:
                    digits.append(digit)
                    remaining -= digit
                    break
                rank -= bucket
            else:
                raise AssertionError("rank exceeds available suffixes")
        assert remaining == rank == 0
        return digits

    def rank(self, digits):
        if len(digits) != len(self.radices):
            raise ValueError("wrong digit count")
        remaining = self.digit_sum
        rank = 0
        for i, (digit, radix) in enumerate(zip(digits, self.radices)):
            if not isinstance(digit, int) or not 0 <= digit < radix or digit > remaining:
                raise ValueError("digit exceeds its radix or remaining sum")
            rank += sum(
                self.counts[i + 1][remaining - smaller]
                for smaller in range(digit)
            )
            remaining -= digit
        if remaining:
            raise ValueError("wrong digit sum")
        return rank


ENCODING = Encoding(RADICES, DIGIT_SUM)
assert ENCODING.size >= MESSAGE_SPACE


def encode_message(message):
    if len(message) != 20:
        raise ValueError("message must contain exactly 20 bytes")
    return ENCODING.unrank(int.from_bytes(message, "big"))


def decode_message(digits):
    rank = ENCODING.rank(digits)
    if rank >= MESSAGE_SPACE:
        raise ValueError("codeword is outside the 20-byte message image")
    return rank.to_bytes(20, "big")


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def scriptnum(value):
    if value == 0:
        return b""
    negative = value < 0
    magnitude = abs(value)
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


def chain_witness(node, digit, style):
    if style == "numeric":
        return [node, scriptnum(digit)]
    if style == "strided":
        return [scriptnum(digit // 2), node, scriptnum(1 - digit % 2)]
    raise ValueError("unknown witness style")


def exact_witness_moments(encoding, native_bytes, start_bytes, style, limit):
    """Integer sum and attained maximum over ranks [0, limit)."""
    if not 0 < limit <= encoding.size:
        raise ValueError("invalid message-space size")
    radices, target, counts = encoding.radices, encoding.digit_sum, encoding.counts
    n = len(radices)
    costs = [
        sum(len(compact_size(len(item))) + len(item) for item in chain_witness(
            bytes(start_bytes if digit == 0 else native_bytes), digit, style
        ))
        for digit in range(max(radices))
    ]
    totals = [[0] * (target + 1) for _ in range(n + 1)]
    maxima = [[0] * (target + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for remaining in range(target + 1):
            for digit in range(min(radices[i], remaining + 1)):
                count = counts[i + 1][remaining - digit]
                if count:
                    totals[i][remaining] += (
                        totals[i + 1][remaining - digit] + count * costs[digit]
                    )
                    maxima[i][remaining] = max(
                        maxima[i][remaining], maxima[i + 1][remaining - digit] + costs[digit]
                    )

    def prefix(i, remaining, bound):
        if bound == counts[i][remaining]:
            return totals[i][remaining], maxima[i][remaining]
        total = maximum = 0
        for digit in range(min(radices[i], remaining + 1)):
            take = min(bound, counts[i + 1][remaining - digit])
            if take:
                suffix_total, suffix_max = prefix(i + 1, remaining - digit, take)
                total += suffix_total + take * costs[digit]
                maximum = max(maximum, suffix_max + costs[digit])
                bound -= take
            if not bound:
                break
        assert bound == 0
        return total, maximum

    total, maximum = prefix(0, target, limit)
    item_count = n * (2 if style == "numeric" else 3)
    framing = len(compact_size(item_count))
    return total + framing * limit, maximum + framing


@lru_cache(maxsize=None)
def profile_moments(native_bytes, start_bytes, style):
    total, maximum = exact_witness_moments(
        ENCODING, native_bytes, start_bytes, style, MESSAGE_SPACE
    )
    mean = Fraction(total, MESSAGE_SPACE)
    return {
        "mean_bytes": float(mean),
        "mean_numerator": str(mean.numerator),
        "mean_denominator": str(mean.denominator),
        "maximum_bytes": maximum,
    }


def baseline_checksum_digits(message_digit_sum, message_digits):
    checksum = 15 * message_digits - message_digit_sum
    return (checksum & 7, (checksum >> 3) & 7, checksum >> 6)


def baseline_numeric_moments(native_bytes, message_digits=40):
    """Exact sum/max for uniform base-16 digits and the [3,3,4] checksum.

    All starts are 16 bytes. The smaller message_digits argument is used only
    for the brute-force recurrence check; its checksum layout remains fixed.
    """
    def item_cost(digit):
        return native_bytes + 3 - (native_bytes - 15) * (digit == 0)

    counts, totals, maxima = [1], [0], [0]
    for _ in range(message_digits):
        next_counts = [0] * (len(counts) + 15)
        next_totals = [0] * len(next_counts)
        next_maxima = [0] * len(next_counts)
        for previous_sum, count in enumerate(counts):
            if count:
                for digit in range(16):
                    new_sum = previous_sum + digit
                    cost = item_cost(digit)
                    next_counts[new_sum] += count
                    next_totals[new_sum] += totals[previous_sum] + count * cost
                    next_maxima[new_sum] = max(
                        next_maxima[new_sum], maxima[previous_sum] + cost
                    )
        counts, totals, maxima = next_counts, next_totals, next_maxima

    message_count = 16 ** message_digits
    assert sum(counts) == message_count
    framing = len(compact_size(2 * (message_digits + 3)))
    total = maximum = 0
    for message_sum, count in enumerate(counts):
        if count:
            checksum_cost = sum(
                item_cost(digit)
                for digit in baseline_checksum_digits(message_sum, message_digits)
            )
            total += totals[message_sum] + count * (checksum_cost + framing)
            maximum = max(maximum, maxima[message_sum] + checksum_cost + framing)
    return total, maximum


def baseline20_numeric_preimage16():
    """Reference costs with the same exact-message distribution as the new code."""
    maximum_message = b"\x78" + b"\x88" * 19
    profiles = {}
    for name, native_bytes in (("hash160", 20), ("sha256", 32)):
        total, maximum = baseline_numeric_moments(native_bytes)
        mean = Fraction(total, MESSAGE_SPACE)
        fixtures = {}
        for label, message in (
            ("zero", bytes(20)),
            ("ff", b"\xff" * 20),
            ("varied", bytes((37 * i) % 256 for i in range(20))),
            ("maximum", maximum_message),
        ):
            digits = [digit for byte in message for digit in (byte >> 4, byte & 15)]
            digits.extend(baseline_checksum_digits(sum(digits), 40))
            items = [
                item for digit in digits
                for item in chain_witness(
                    bytes(16 if digit == 0 else native_bytes), digit, "numeric"
                )
            ]
            fixtures[label] = len(serialize_witness(items))
        assert fixtures["maximum"] == maximum
        profiles[name] = {
            "native_bytes": native_bytes,
            "preimage_bytes": 16,
            "mean_bytes": float(mean),
            "mean_numerator": str(mean.numerator),
            "mean_denominator": str(mean.denominator),
            "maximum_bytes": maximum,
            "fixture_witness_bytes": fixtures,
        }
    return {
        "message_bytes": 20,
        "message_digits": 40,
        "checksum_widths": [3, 3, 4],
        "witness_style": "numeric",
        "witness_items": 86,
        "auxiliary_hint_items": 0,
        "maximum_message": maximum_message.hex(),
        "sha256_hash160_note": "Identical witness sizes to the SHA-256 numeric profile.",
        "profiles": profiles,
    }


def vectors(name, short=True):
    chain_hash = hash160 if name == "hash160" else lambda data: hashlib.sha256(data).digest()
    commit = hash160 if name == "sha256-hash160" else lambda data: data
    native_bytes = 20 if name == "hash160" else 32
    start_bytes = 16 if short else native_bytes
    style = "numeric" if name == "hash160" else "strided"
    namespace = chain_hash(
        DOMAIN
        + f"bitcoin-lab/winternitz-{name}/v1".encode()
        + (PREIMAGE16_DOMAIN if short else b"")
        + bytes(RADICES)
        + DIGIT_SUM.to_bytes(2, "big")
        + SEED
    )
    chains = []
    for i, radix in enumerate(RADICES):
        node = chain_hash(namespace + i.to_bytes(4, "big"))[:start_bytes]
        chain = [node]
        for _ in range(1, radix):
            node = chain_hash(node)
            chain.append(node)
        chains.append(chain)
    endpoints = [commit(chain[-1]) for chain in chains]
    fixtures = {}
    for label, message in (
        ("zero", bytes(20)),
        ("ff", b"\xff" * 20),
        ("varied", bytes((37 * i) % 256 for i in range(20))),
        ("range", bytes(range(20))),
    ):
        digits = encode_message(message)
        assert decode_message(digits) == message
        nodes = [chain[digit] for chain, digit in zip(chains, digits)]
        items = [
            item
            for node, digit in zip(nodes, digits)
            for item in chain_witness(node, digit, style)
        ]
        witness = serialize_witness(items)
        fixtures[label] = {
            "message": message.hex(),
            "digits": digits,
            "signature_sha256": hashlib.sha256(b"".join(nodes)).hexdigest(),
            "witness_sha256": hashlib.sha256(witness).hexdigest(),
            "witness_bytes": len(witness),
        }
    return {
        "public_sha256": hashlib.sha256(b"".join(endpoints)).hexdigest(),
        "native_bytes": native_bytes,
        "commitment_bytes": 20 if name != "sha256" else 32,
        "preimage_bytes": start_bytes,
        "witness_style": style,
        "witness_items": len(RADICES) * (2 if style == "numeric" else 3),
        "auxiliary_hint_items": 0,
        "witness_moments": profile_moments(native_bytes, start_bytes, style),
        "fixtures": fixtures,
    }


def self_check():
    # Brute-force a small independent domain to check both ranking and the
    # weighted-prefix moment recurrence, including partial codeword images.
    toy = Encoding((3, 4, 5), 5)
    words = [
        list(word) for word in itertools.product(range(3), range(4), range(5))
        if sum(word) == 5
    ]
    assert len(words) == toy.size
    for index, word in enumerate(words):
        assert toy.unrank(index) == word and toy.rank(word) == index
    for style in ("numeric", "strided"):
        for width in (20, 32):
            sizes = []
            for word in words:
                items = [
                    item for digit in word
                    for item in chain_witness(bytes(16 if digit == 0 else width), digit, style)
                ]
                sizes.append(len(serialize_witness(items)))
            for limit in range(1, len(words) + 1):
                assert exact_witness_moments(toy, width, 16, style, limit) == (
                    sum(sizes[:limit]), max(sizes[:limit])
                )
    for i in range(256):
        message = hashlib.sha256(i.to_bytes(4, "big")).digest()[:20]
        assert decode_message(encode_message(message)) == message
    # Check the baseline sum/cost DP against explicit serialization of all
    # 256 two-digit messages, retaining the baseline's checksum partition.
    for width in (20, 32):
        sizes = []
        for digits in itertools.product(range(16), repeat=2):
            complete_digits = digits + baseline_checksum_digits(sum(digits), 2)
            items = [
                item for digit in complete_digits
                for item in chain_witness(bytes(16 if digit == 0 else width), digit, "numeric")
            ]
            sizes.append(len(serialize_witness(items)))
        assert baseline_numeric_moments(width, message_digits=2) == (sum(sizes), max(sizes))
    for digits in ([0] * len(RADICES), [0] * (len(RADICES) - 1), ENCODING.unrank(MESSAGE_SPACE)):
        try:
            decode_message(digits)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed or unused codeword decoded")


if __name__ == "__main__":
    self_check()
    print(json.dumps({
        "seed": SEED.hex(),
        "radices": RADICES,
        "digit_sum": DIGIT_SUM,
        "codeword_count": str(ENCODING.size),
        "encoded_message_count": str(MESSAGE_SPACE),
        "baseline20_numeric_preimage16": baseline20_numeric_preimage16(),
        "profiles": {
            f"{name}/{'preimage16' if short else 'native'}": vectors(name, short)
            for name in ("hash160", "sha256", "sha256-hash160")
            for short in (True, False)
        },
    }, indent=2))
