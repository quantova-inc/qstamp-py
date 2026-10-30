# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from ._bech32m import address_bytes

_ALG_IDS = {"sha3-256": 1, "sha256": 2}
_LEAF_TAG = b"QSTAMP/LEAF/V1"
_ROOT_TAG = b"QSTAMP/ROOT/V1"
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_ROOT_PREFIX = b"\x02"
_MAX_LEAVES = 1 << 20
_MAX_PATH = 20
_MAX_U64 = (1 << 64) - 1

_GENESIS_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_KIND_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")


def _sha3(*parts):
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


def _algorithm_id(name):
    if name not in _ALG_IDS:
        raise ValueError(f"unsupported digest algorithm {name!r}")
    return _ALG_IDS[name]


def leaf_hash(alg, digest, salt):
    aid = _algorithm_id(alg)
    if len(digest) != 32:
        raise ValueError("a digest is 32 bytes")
    if len(salt) != 32:
        raise ValueError("a salt is 32 bytes")
    return _sha3(_LEAF_PREFIX, _LEAF_TAG, bytes([aid]), digest, salt)


def _node_hash(left, right):
    return _sha3(_NODE_PREFIX, left, right)


def _kind_word(kind):
    if not _KIND_RE.match(kind):
        raise ValueError("the record kind must be a decimal string")
    k = int(kind)
    if k > _MAX_U64:
        raise ValueError("the record kind must fit in 64 bits")
    return k.to_bytes(8, "big")


def _parse_genesis(genesis):
    if not _GENESIS_RE.match(genesis):
        raise ValueError("the genesis hash must be 64 lowercase hexadecimal characters")
    return bytes.fromhex(genesis)


@dataclass(frozen=True)
class CommitmentContext:
    genesis: str
    contract: str
    sender: str
    kind: str


def commitment(root, size, ctx):
    if len(root) != 32:
        raise ValueError("a root is 32 bytes")
    if size < 1 or size > _MAX_LEAVES:
        raise ValueError("a batch size is out of range")
    genesis = _parse_genesis(ctx.genesis)
    try:
        contract = address_bytes(ctx.contract)
    except ValueError as exc:
        raise ValueError("the contract is not a Quantova address") from exc
    try:
        sender = address_bytes(ctx.sender)
    except ValueError as exc:
        raise ValueError("the sender is not a Quantova address") from exc
    kind = _kind_word(ctx.kind)
    s = size.to_bytes(8, "big")
    return _sha3(_ROOT_PREFIX, _ROOT_TAG, genesis, contract, sender, kind, s, root)


def root_from_path(leaf, index, size, path):
    if len(leaf) != 32:
        return None
    if size < 1 or size > _MAX_LEAVES:
        return None
    if index < 0 or index >= size:
        return None
    if len(path) > _MAX_PATH:
        return None
    fn = index
    sn = size - 1
    r = leaf
    for p in path:
        if len(p) != 32:
            return None
        if sn == 0:
            return None
        if fn & 1 == 1 or fn == sn:
            r = _node_hash(p, r)
            while fn & 1 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            r = _node_hash(r, p)
        fn //= 2
        sn //= 2
    if sn != 0:
        return None
    return r


@dataclass
class Record:
    alg: str
    digest: str
    salt: str


@dataclass
class Proof:
    index: int
    size: int
    path: list = field(default_factory=list)


@dataclass
class Receipt:
    chain_genesis: str
    contract: str
    kind: str
    sender: str
    record: Record
    proof: Proof
    root: str
    chain_id: str = ""
    tx: str = ""

    @staticmethod
    def from_json(obj):
        rec = obj["record"]
        pr = obj["proof"]
        anchor = obj.get("anchor", {})
        return Receipt(
            chain_genesis=obj["chain"]["genesis"],
            chain_id=obj.get("chain", {}).get("id", ""),
            contract=obj["contract"],
            kind=obj["kind"],
            sender=anchor.get("sender", ""),
            record=Record(alg=rec["alg"], digest=rec["digest"], salt=rec["salt"]),
            proof=Proof(index=pr["index"], size=pr["size"], path=list(pr.get("path", []))),
            root=obj["root"],
            tx=anchor.get("tx", ""),
        )


@dataclass(frozen=True)
class Result:
    root_matches: bool
    commitment: bytes

    @property
    def commitment_hex(self):
        return self.commitment.hex()


def _parse32(value, what):
    if not _HEX64_RE.match(value):
        raise ValueError(f"{what} is 32 bytes written as 64 hexadecimal characters")
    return bytes.fromhex(value)


def recompute(receipt):
    digest = _parse32(receipt.record.digest, "a digest")
    salt = _parse32(receipt.record.salt, "a salt")
    leaf = leaf_hash(receipt.record.alg, digest, salt)
    root = _parse32(receipt.root, "a root")
    path = [_parse32(step, "a path node") for step in receipt.proof.path]
    rebuilt = root_from_path(leaf, receipt.proof.index, receipt.proof.size, path)
    matches = rebuilt is not None and rebuilt == root
    ctx = CommitmentContext(
        genesis=receipt.chain_genesis,
        contract=receipt.contract,
        sender=receipt.sender,
        kind=receipt.kind,
    )
    c = commitment(root, receipt.proof.size, ctx)
    return Result(root_matches=matches, commitment=c)
