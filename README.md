# bitflip

Derive a bitcoin BIP39 seed phrase from physical coin flips.

You flip a coin, you type H or T, you get the words. Single file, Python 3.8+
standard library only, no dependencies, no network access, nothing written to
disk. It never calls `os.urandom`, `secrets` or `random` — every bit of a seed
it produces came from a coin or from your fingers.

**Run this on an airgapped machine.**

screenshot:
<img width="1390" height="1584" alt="1" src="https://github.com/user-attachments/assets/90ae650a-26c7-4e69-b81a-a4795d9a010a" />


## Usage

```
python3 bitflip.py                   # interactive, guided entry
python3 bitflip.py HTTHHTTH...       # the whole flip string as an argument
```

Run bare and it asks for 12 or 24 words, then takes your flips in groups of 11,
naming each word as its group completes. Or pass the whole string — 128 or 256
flips, H/1 = heads, T/0 = tails. It then asks for a passphrase (the BIP39 25th
word), typed twice to confirm, and finishes by printing the BIP32 master
fingerprint and xpub — re-derive those on a second, independent tool and compare
them. A passphrase has no checksum, so a matching fingerprint is the only
confirmation you get that you typed the one you meant to.

Compare the **fingerprint**. The xpub printed is the master key at `m`, and a
wallet does not show you that one — Sparrow shows the account key at
`m/84'/0'/0'`, three levels down, which shares no bytes with it and is not meant
to. A mismatch there is not a derivation bug; the fingerprint is the line the
two tools should agree on.

It also prints a **watch-only descriptor** for the native segwit account:

```
wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT…/<0;1>/*)#qf45pmyh
```

Import that to watch the wallet from a phone or a laptop without the words ever
being typed there. It carries the four things a bare xpub does not: the script
type, which seed (the fingerprint), which branch, and the key — a bare xpub
leaves the script type to be guessed, and a wrong guess watches the wrong
addresses and reports a zero balance. Note that this descriptor reveals every
address the account will ever use, so whoever holds it can watch the balance and
the whole payment history forever. It cannot spend.

It then prints the same account as a **spending descriptor**, with an `xprv`
instead of the `xpub`. Bitcoin Core has no BIP39 in it — no RPC mentions a
mnemonic or a seed phrase — so a node cannot be the wallet for these words until
they have been turned into a key. This is that key, in the form Core imports:

```
bitcoin-cli -named createwallet wallet_name=coinflip blank=true
bitcoin-cli -rpcwallet=coinflip importdescriptors \
  '[{"desc":"wpkh([73c5da0a/84h/0h/0h]xprv9ybY78BftS5UG…/<0;1>/*)#aeunql2k","active":true,"timestamp":<seed creation time>}]'
```

Core will then sign and spend on its own. Two things to be clear about before
using it. This line is worth exactly what the words are worth — whoever reads it
owns the account. And it is sufficient on its own, so a BIP39 passphrase stops
protecting anything the moment it exists: the point of a passphrase is that the
words alone are not enough, and this string is. If you want the passphrase to
keep meaning something, import the watch-only descriptor instead and sign
somewhere the key is not online.

Keep a passphrase to ASCII if you can. BIP39 requires NFKD normalisation before
hashing and not every wallet does it, so a passphrase with accents in it can
restore a different wallet elsewhere from the same keystrokes. This tool
normalises, matches Trezor's reference implementation, and warns when what you
typed is not ASCII.

One flip is one bit.

| words | entropy | flips |
|-------|---------|-------|
| 12    | 128     | 128   |
| 24    | 256     | 256   |

Press **`r`** instead of typing a flip and it takes the nanosecond your finger
arrived, keeping one bit of it.

## Why human entropy

A CSPRNG's output is a deterministic function of its seed. `os.urandom(32)` is
256 bits *if* the kernel's entropy pool was properly seeded and *if* ChaCha20 is
a pseudorandom function. Both are assumptions. The second is a good one. The
first is where the money has actually gone:

- **Debian OpenSSL, 2008** — a removed line narrowed the keyspace to 32,767
  possibilities, for every key generated over two years.
- **Android `SecureRandom`, 2013** — bitcoin wallets generated colliding
  signature nonces and were swept.
- **Mining Your Ps and Qs, 2012** — boot-time entropy starvation left tens of
  thousands of TLS and SSH hosts sharing factorable keys.
- **Milk Sad, 2023** — `libbitcoin-explorer` seeded a Mersenne Twister with a
  32-bit timestamp. Millions of dollars, from a tool whose whole job was seeds.
- **Coldcard, 2026** — a build flag left the STM32 hardware TRNG disabled, so
  five years of seeds, across every model they ship, came from a software PRNG
  keyed on the chip ID and boot counter. The weakest held about 40 bits. 1,083
  BTC left 1,196 addresses in 41 minutes on 30 July; it is still draining as
  this is written.

A broken RNG and a good one are indistinguishable from their output, so you cannot test your way to trust, and you cannot audit an RNG at runtime — you can only read the code and hope it is the code that ran.

256 coin flips need none of that. They are 256 bits because the coin does not know either, and no amount of computation recovers what was never determined. No cipher to break, no pool to have been empty at boot. Which matters most in exactly the situation this tool is for: a freshly booted airgapped machine or a live USB, where the pool is youngest and the historical failure rate is highest.

The `r` key is physical entropy too. The bit comes from the nanosecond that your finger landed, not from a state machine, and it is read through your machine's clock — so the script measures that clock before it will accept a single press, and refuses to toss at all if the tick is too coarse to carry a bit.

## License

MIT
