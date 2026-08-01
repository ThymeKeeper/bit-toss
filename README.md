# bit-toss

Derive a bitcoin BIP39 seed phrase from physical coin flips.

You flip a coin, you type H or T, you get the words. No RNG, no library you have
to trust, no dependencies — Python 3.8+ standard library only, single file, no
network access, nothing written to disk.

**Run this on an airgapped machine.** A seed phrase typed into a networked
computer is a seed phrase you should assume is compromised.

<img width="1435" height="1427" alt="seed generator" src="https://github.com/user-attachments/assets/11c5d125-d849-4c1a-b689-b0c842ec5781" />

## Usage

```
python3 bit_toss.py                  # interactive, guided entry
python3 bit_toss.py HTTHHTTH...      # the whole flip string as an argument
```

Run bare and the script asks whether you want a 12- or 24-word seed, then takes
your flips in groups of 11. Or pass the whole flip string as an argument —
128 or 256 flips, H/1 = heads, T/0 = tails, whitespace and dashes ignored —
and the word count is inferred from the length.

Other flags: `--passphrase` (BIP39 25th word).

Every derivation prints:

- the 12–24 mnemonic words
- the BIP32 master fingerprint
- the 512-bit BIP39 seed, in hex
- the BIP32 master private key, as an importable `xprv...`, plus the raw
  32-byte key and chain code in hex

These are all the same secret in different notations. The `xprv` is the actual
private key the mnemonic expands into — everything in the wallet derives from
it, so it is exactly as dangerous as the words and deserves the same handling.

If you pass a passphrase, every one of those except the words reflects it.

In guided mode you enter 11 flips at a time and each complete group reveals its
word immediately, so you can follow along on paper. The final group is short —
the remaining bits of the last word are the BIP39 checksum.

## How many flips?

One flip is one bit. A 24-word seed is 256 bits of entropy, so 256 flips; a
12-word seed is 128. The checksum bits are computed, not flipped.

| words | entropy | flips |
|-------|---------|-------|
| 12    | 128     | 128   |
| 24    | 256     | 256   |

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
- BIP32 master key derivation and base58check, for the `xprv`

## License

MIT
