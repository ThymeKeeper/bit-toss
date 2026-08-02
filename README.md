# bitflip

Derive a bitcoin BIP39 seed phrase from physical coin flips.

You flip a coin, you type H or T, you get the words. No library you have to
trust, no dependencies — Python 3.8+ standard library only, single file, no
network access, nothing written to disk.

No RNG either. Not "no RNG by default" — this file never calls `os.urandom`,
`secrets` or `random` at all. Every bit of a seed it produces came from a coin
or from your fingers; see
[When you don't want to flip 256 times](#when-you-dont-want-to-flip-256-times).

**Run this on an airgapped machine.** A seed phrase typed into a networked
computer is a seed phrase you should assume is compromised.

screenshot:
<img width="1088" height="1537" alt="screenshot" src="https://github.com/user-attachments/assets/89a90dbb-fb32-46f0-aced-459a011c914a" />

## Usage

```
python3 bitflip.py                   # interactive, guided entry
python3 bitflip.py HTTHHTTH...       # the whole flip string as an argument
```

Run bare and the script asks whether you want a 12- or 24-word seed, then takes
your flips in groups of 11. Or pass the whole flip string as an argument —
128 or 256 flips, H/1 = heads, T/0 = tails, whitespace and dashes ignored —
and the word count is inferred from the length.

Other flags: `--passphrase` (BIP39 25th word).

Every derivation prints:

- the 12–24 mnemonic words
- the BIP32 master private key, as an importable `xprv...`, plus the raw
  32-byte key and chain code in hex

These are the same secret in two notations. The `xprv` is the actual private key
the mnemonic expands into — everything in the wallet derives from it, so it is
exactly as dangerous as the words and deserves the same handling. It is also
what you check against a second tool.

If you pass a passphrase, the `xprv` reflects it and the words do not.

In guided mode you enter 11 flips at a time and each complete group reveals its
word immediately, so you can follow along on paper. The final group is short —
the remaining bits of the last word are the BIP39 checksum.

At a real terminal, keys are read one at a time, so a flip lands the moment you
press it and backspace takes it back.

## When you don't want to flip 256 times

Press **`r`** instead of typing a flip. It takes the nanosecond your finger
arrived and keeps one bit of it.

**You have to press it deliberately.** An `r` only counts if the preceding
100 ms contained no keystroke at all. Hold the key down and the repeats earn
nothing — the group simply stops filling and the line says `too fast, press r
slowly` until you let go. A paste is refused the same way, and structurally too:
its characters all arrive in a single `read()`, which is proof they were queued
rather than pressed.

That debounce measures from the last keystroke of *any* kind, not the last one
that counted, and the distinction is the whole mechanism. Debouncing against the
last accepted press would let a key repeating every 33 ms have every other
repeat accepted — a decimated 15 Hz stream that is *more* regular than what it
came from and just as much the scheduler's work.

Pressing too fast is never destructive: the keystroke is ignored, not the group.
Measured over 20 000 simulated sessions, a group is discarded **0.0000 %** of
the time at every human typing rate. The only rule that discards one is a check
for *evenness* — ten presses in a row within 10 % of the same interval. That is
what a repeat timer looks like, but a hand tapping to a beat can drift into it
too, so it just asks you to vary the rhythm and retype that group.

Why guard it at all, given that a held key still measures 0.87–0.92 bits per
press? Because of *where those bits come from*, not how many there are. Nobody
can put a pattern into a nanosecond — tty delivery jitter is ~92 µs and parity
only degrades below ~10 ns of jitter, a margin of ten thousand — so a held key
does produce unpredictable bits. They are just the **scheduler's**
unpredictability rather than yours: interrupt timing on this particular machine,
which is the one thing this tool is built to avoid having to trust. The debounce
keeps your hand in the loop. It is not there because held-key bits are worthless;
it is there because they are the machine's.

It also measures the clock's true tick before the first toss and divides by it,
and refuses to toss at all if the tick is coarser than 10 µs or if it cannot
measure one. Without that step, on a 100 ns clock — ordinary Windows QPC, WSL2,
most VMs — every raw nanosecond is even, every toss comes out tails, and you get
`abandon abandon … art` with a checksum every wallet accepts. The bit is taken
as the low bit of the tick count *precisely because* that is how it fails: if
the measurement is ever wrong, you get a screen full of zeros rather than
plausible-looking bits that are worth nothing.

## How many flips?

One flip is one bit. A 24-word seed is 256 bits of entropy, so 256 flips; a
12-word seed is 128. The checksum bits are computed, not flipped.

(One *coin flip* is one bit. One `r` press is also charged as one bit, but that
is a deliberate 8× under-claim: a keypress arrival time carries something like
8–11 bits of measurable jitter and the tool takes one of them. Under-claiming is
the whole reason it is safe.)

| words | entropy | flips |
|-------|---------|-------|
| 12    | 128     | 128   |
| 24    | 256     | 256   |

## Verify before you fund anything

One tool agreeing with itself proves nothing. Re-enter the *same* flips into a
second, independent implementation — SeedSigner, Coldcard, an offline copy of
Ian Coleman's BIP39 tool — and confirm that both the words **and** the `xprv`
match.

Then:

1. Write the words on something durable.
2. Test the backup by restoring it into a watch-only wallet before sending funds.
3. Destroy the paper record of the raw flips.
4. Close the terminal and clear its scrollback.

Tossed bits have no paper record — nothing exists before the tool runs — so
there is nothing to re-enter. Check those seeds forwards instead: restore the
words in a second tool and confirm it derives the same `xprv`. That verifies
this file's BIP39 and BIP32 arithmetic against an independent implementation,
which is worth doing, but unlike the coin-flip case it cannot vouch for where
the bits came from.

## What's in the file

Everything needed is inlined so the script can run with no installs on an
offline machine:

- the full 2048-word BIP39 English wordlist, checked against a SHA-256 digest at
  startup so a tampered copy refuses to run
- a pure-Python RIPEMD-160, because OpenSSL 3.x moved it to the legacy provider
  and `hashlib` usually can't supply it
- just enough secp256k1 to turn the BIP32 master key into a compressed public
  key, which the startup self-check needs to verify its own derivation
- BIP32 master key derivation and base58check, for the `xprv`
- a single-keypress reader (`termios` on Unix, `msvcrt` on Windows) that keeps
  `ISIG` set so Ctrl-C is still generated by the terminal driver rather than by
  us, and restores the terminal on every exit path including Ctrl-Z

## Why there is no entropy score

A number at the end saying how random your seed is would be the most reassuring
thing this tool could print, and it would be a lie. Not "imprecise" — actively
inverted. Scoring 256-bit samples with SP 800-90B's *most generous* estimator:

| source | actual entropy | score |
|--------|---------------|-------|
| `os.urandom` | 256 bits | **189** |
| biased coin, p(1) = 0.6 | ~194 bits | **117** |
| `sha256(counter)` | **0 bits** | **168** |

A source worth exactly nothing outscores a real but slightly biased one, and a
perfect source scores 189 rather than 256 because at n = 256 the sampling error
alone is larger than the entire gap between a good seed and a dead one. SP
800-90B asks for a million samples; a seed gives you 256. There is no estimator,
however clever, that fixes this — the information simply is not there.

Worse, the failures that actually matter are the ones no test can see. A held-
down `r` key measures 0.87–0.92 bits per press and passes everything, while the
person made one decision instead of 256. `sha256(counter)` passes dieharder,
monobit, chi-square and every compressor. The one and only defence against those
is knowing *where each bit came from*, which is why the tool counts provenance
instead of scoring randomness.

What it does check is exact equality against entropy already known to be dead —
the published BIP39 vectors, whose wallets are watched by bots and emptied on
funding, and constant-byte patterns that only a broken input path produces. That
is a bug detector, not a measurement: a real coin lands on one of those with
probability about 2⁻²⁴⁸, so it can only ever fire on a fault.

There is likewise deliberately **no statistical test** on the tossed bits.
Hashing does not create entropy — SHA-256 of a 20-bit source still has 20 bits
of it, and still passes monobit, chi-square, dieharder and every compressor. And
a test could not tell you the thing you want to know anyway: a held-down key and
a deliberate one both measure around 0.9 bits per press, because the difference
between them is not in the numbers, it is in whose unpredictability they are.
The guards are structural for that reason — they check that the keypresses
happened, which is decidable — and the provenance count is the honest substitute
for a green tick.

Before it will take a single flip, the script derives the published BIP39 and
BIP32 test vectors and refuses to run if any of them come out wrong. This is not
optional and there is no flag for it, because the failure it guards against is
invisible. A wallet checks the words you type into it — that they are real
wordlist entries and that the checksum matches — so a bug in the path that
produces the words gets caught the moment you restore. Nothing checks what
happens after. A broken PBKDF2 or BIP32 would still hand you a phrase every
wallet accepts, while the `xprv` printed alongside it quietly
belonged to a different wallet.

## License

MIT
