# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qstamp import CommitmentContext, Receipt, commitment, leaf_hash, recompute, root_from_path  # noqa: E402
from qstamp._verify import Proof, Record  # noqa: E402

DATA = os.path.join(os.path.dirname(__file__), "data")


def _load(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return json.load(f)


class ConformanceToReferenceSDK(unittest.TestCase):
    def test_leaf_hash_matches_sdk(self):
        v = _load("vectors.json")
        for i, r in enumerate(v["records"]):
            leaf = leaf_hash(r["alg"], bytes.fromhex(r["digest"]), bytes.fromhex(r["salt"]))
            self.assertEqual(leaf.hex(), v["leaves"][i], f"leaf {i}")

    def test_root_from_path_matches_sdk(self):
        v = _load("vectors.json")
        for r in v["records"]:
            leaf = leaf_hash(r["alg"], bytes.fromhex(r["digest"]), bytes.fromhex(r["salt"]))
            path = [bytes.fromhex(p) for p in r["path"]]
            root = root_from_path(leaf, r["index"], v["size"], path)
            self.assertIsNotNone(root)
            self.assertEqual(root.hex(), v["root"])
            self.assertEqual(root.hex(), r["rebuilt"])

    def test_commitment_matches_sdk(self):
        v = _load("vectors.json")
        ctx = CommitmentContext(genesis=v["genesis"], contract=v["contract"], sender=v["sender"], kind=v["kind"])
        c = commitment(bytes.fromhex(v["root"]), v["size"], ctx)
        self.assertEqual(c.hex(), v["commitment"])

    def test_corpus_differential(self):
        cases = _load("corpus.json")
        self.assertGreater(len(cases), 0)
        checks = 0
        for case in cases:
            ctx = CommitmentContext(genesis=case["genesis"], contract=case["contract"], sender=case["sender"], kind=case["kind"])
            c = commitment(bytes.fromhex(case["root"]), case["size"], ctx)
            self.assertEqual(c.hex(), case["commitment"], f"case {case['id']} size {case['size']} commitment")
            for ch in case["checks"]:
                leaf = leaf_hash(ch["alg"], bytes.fromhex(ch["digest"]), bytes.fromhex(ch["salt"]))
                path = [bytes.fromhex(p) for p in ch["path"]]
                root = root_from_path(leaf, ch["index"], case["size"], path)
                self.assertIsNotNone(root)
                self.assertEqual(root.hex(), case["root"], f"case {case['id']} idx {ch['index']}")
                checks += 1
        self.assertGreater(checks, 100)


class NegativeCases(unittest.TestCase):
    def test_tampered_digest_breaks_root(self):
        v = _load("vectors.json")
        r = v["records"][0]
        bad = bytearray(bytes.fromhex(r["digest"]))
        bad[0] ^= 0x01
        receipt = Receipt(
            chain_genesis=v["genesis"],
            contract=v["contract"],
            kind=v["kind"],
            sender=v["sender"],
            record=Record(alg=r["alg"], digest=bytes(bad).hex(), salt=r["salt"]),
            proof=Proof(index=r["index"], size=v["size"], path=r["path"]),
            root=v["root"],
        )
        res = recompute(receipt)
        self.assertFalse(res.root_matches)

    def test_wrong_index_fails(self):
        v = _load("vectors.json")
        r = v["records"][0]
        leaf = leaf_hash(r["alg"], bytes.fromhex(r["digest"]), bytes.fromhex(r["salt"]))
        path = [bytes.fromhex(p) for p in r["path"]]
        wrong = (r["index"] + 1) % v["size"]
        root = root_from_path(leaf, wrong, v["size"], path)
        if root is not None:
            self.assertNotEqual(root.hex(), v["root"])

    def test_out_of_range_inputs(self):
        leaf = b"\x00" * 32
        self.assertIsNone(root_from_path(leaf, 0, 0, []))
        self.assertIsNone(root_from_path(leaf, -1, 4, []))
        self.assertIsNone(root_from_path(leaf, 4, 4, []))
        self.assertIsNone(root_from_path(b"\x00" * 31, 0, 1, []))
        with self.assertRaises(ValueError):
            commitment(b"\x00" * 31, 1, CommitmentContext("00" * 32, "x", "y", "1"))

    def test_recompute_end_to_end(self):
        v = _load("vectors.json")
        r = v["records"][2]
        receipt = Receipt(
            chain_genesis=v["genesis"],
            contract=v["contract"],
            kind=v["kind"],
            sender=v["sender"],
            record=Record(alg=r["alg"], digest=r["digest"], salt=r["salt"]),
            proof=Proof(index=r["index"], size=v["size"], path=r["path"]),
            root=v["root"],
        )
        res = recompute(receipt)
        self.assertTrue(res.root_matches)
        self.assertEqual(res.commitment_hex, v["commitment"])

    def test_address_round_trip(self):
        v = _load("vectors.json")
        from qstamp._bech32m import address_bytes

        for a in (v["contract"], v["sender"]):
            self.assertEqual(len(address_bytes(a)), 32)


if __name__ == "__main__":
    unittest.main()
