# bit-toss

Derive a BIP39 seed phrase from physical coin flips.

You flip a coin, you type H or T, you get the words. No RNG, no library you have
to trust, no dependencies — Python 3.8+ standard library only, single file, no
network access, nothing written to disk.

**Run this on an airgapped machine.** A seed phrase typed into a networked
computer is a seed phrase you should assume is compromised.

## Usage

```
python3 bit_toss.py                  # interactive, guided entry (24 words)
python3 bit_toss.py --words 12       # 12-word seed (128 flips)
python3 bit_toss.py --bulk           # paste the whole flip string at once
python3 bit_toss.py --debias         # von Neumann pair debiasing
python3 bit_toss.py --selftest       # run BIP39 test vectors and exit
```

Other flags: `--passphrase` (BIP39 25th word).

Every derivation prints the words, the BIP32 master fingerprint, and the
512-bit BIP39 seed in hex. If you pass a passphrase, the fingerprint and the
seed both reflect it; the words do not.

In guided mode you enter 11 flips at a time and each complete group reveals its
word immediately, so you can follow along on paper. The final group is short —
the remaining bits of the last word are the BIP39 checksum.

## How many flips?

One flip is one bit. A 24-word seed is 256 bits of entropy, so 256 flips; a
12-word seed is 128. The checksum bits are computed, not flipped.

| words | entropy | flips |
|-------|---------|-------|
| 12    | 128     | 128   |
| 15    | 160     | 160   |
| 18    | 192     | 192   |
| 21    | 224     | 224   |
| 24    | 256     | 256   |

## Debiasing

A real coin is not perfectly fair, and a real human is not a perfect flipper.
`--debias` applies von Neumann extraction: flip in pairs, HT becomes 1, TH
becomes 0, HH and TT are discarded. The output is unbiased for any fixed coin
bias, at the cost of roughly 4x the flips.

If your coin and your flip are honest, plain mode is fine. If you want the
guarantee without having to trust either, use `--debias`.

## Verify before you fund anything

One tool agreeing with itself proves nothing. Re-enter the *same* flips into a
second, independent implementation — SeedSigner, Coldcard, an offline copy of
Ian Coleman's BIP39 tool — and confirm that both the words **and** the master
fingerprint match.

Then:

1. Write the words on something durable.
2. Test the backup by restoring it into a watch-only wallet before sending funds.
3. Destroy the paper record of the raw flips.
4. Close the terminal and clear its scrollback.

## What's in the file

Everything needed is inlined so the script can run with no installs on an
offline machine:

- the full 2048-word BIP39 English wordlist, checked against a SHA-256 digest at
  startup so a tampered copy refuses to run
- a pure-Python RIPEMD-160, because OpenSSL 3.x moved it to the legacy provider
  and `hashlib` usually can't supply it
- just enough secp256k1 to turn the BIP32 master key into a compressed public
  key, so the tool can show you a fingerprint to cross-check against

`--selftest` runs the official BIP39 test vectors plus a known-good fingerprint,
and runs automatically before every derivation. It refuses to proceed if it
fails.

## License

MIT
