# qstamp-py

A pure Python verifier for Qstamp evidence receipts.

Qstamp binds a record digest to a Merkle root and binds the root to a 32 byte commitment that is anchored as a transaction on the Quantova network. This library recomputes that commitment from a receipt and the original record offline, so a verifier confirms the binding without trusting the issuer.

The record itself never leaves the holder. Only the 32 byte commitment is public, so a verifier proves that a record existed in one exact form at the anchored time while the content stays private.

## Why Python

The reference Qstamp SDK is written in JavaScript. This library is an independent Python implementation of the verification path for Python toolchains and agent frameworks, built so provenance and audit code can confirm a Qstamp anchor natively. It depends only on the standard library. SHA3 comes from hashlib.

## Install

```
pip install qstamp
```

## Use

```python
import qstamp

receipt = qstamp.Receipt.from_json(receipt_json)
result = qstamp.recompute(receipt)
if not result.root_matches:
    raise ValueError("the record does not rebuild the receipt root")
# result.commitment_hex is the 32 byte value that must be anchored on chain.
```

## What it checks

1. The record digest and its Merkle path rebuild the root named in the receipt.
2. The root, the batch size, the genesis, the contract, the sender and the kind derive the exact 32 byte commitment.

## Conformance

The verification primitives are checked against the reference Qstamp SDK over batch sizes from 1 to 2048 and both digest algorithms, and the output agrees to the byte. The same vectors verify the JavaScript reference and the Go verifier, so all three agree. Run the suite with the command below.

## Tests

```
python -m unittest discover -s tests
```

The suite covers the conformance vectors, a wider differential corpus, the negative cases where a tampered record or a wrong index must fail, out of range inputs, and the address decode.

## License

Apache 2.0 or MIT. See the LICENSE files.
