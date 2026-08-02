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
flips, H/1 = heads, T/0 = tails. It then asks for a passphrase (the BIP39 25th word).

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
