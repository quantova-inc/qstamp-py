# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_MAX_ENCODED = 128

_REVERSE = {c: i for i, c in enumerate(_CHARSET)}


def _polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for bit in range(5):
            if (top >> bit) & 1:
                chk ^= _GENERATOR[bit]
    return chk & 0xFFFFFFFF


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits_to_8(data):
    acc = 0
    bits = 0
    out = bytearray()
    for value in data:
        if value >> 5 != 0:
            raise ValueError("value out of range")
        acc = ((acc << 5) | value) & 0xFFF
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc << (8 - bits)) & 0xFF != 0:
        raise ValueError("invalid padding")
    return bytes(out)


def decode_address(text, expected_hrp, expected_length):
    if not text:
        raise ValueError("the identifier is empty")
    if len(text) > _MAX_ENCODED:
        raise ValueError("the identifier is too long")
    has_lower = text != text.upper()
    has_upper = text != text.lower()
    if has_lower and has_upper:
        raise ValueError("the identifier mixes upper and lower case")
    lowered = text.lower()
    separator = lowered.rfind("1")
    if separator < 1 or separator + 7 > len(lowered):
        raise ValueError("the identifier has no separator")
    hrp = lowered[:separator]
    for ch in hrp:
        if ord(ch) < 33 or ord(ch) > 126:
            raise ValueError("the identifier prefix holds a bad character")
    if hrp != expected_hrp.lower():
        raise ValueError("the identifier carries the wrong prefix")
    groups = []
    for ch in lowered[separator + 1 :]:
        idx = _REVERSE.get(ch, -1)
        if idx < 0:
            raise ValueError("the identifier holds a character outside the alphabet")
        groups.append(idx)
    if _polymod(_hrp_expand(hrp) + groups) != _BECH32M_CONST:
        raise ValueError("the identifier checksum does not verify")
    payload = _convert_bits_to_8(groups[: len(groups) - 6])
    if expected_length >= 0 and len(payload) != expected_length:
        raise ValueError("the identifier does not hold the expected number of bytes")
    return payload


def address_bytes(address):
    return decode_address(address, "Q", 32)
