#!/usr/bin/env python3
"""
bitflip.py -- derive a BIP39 mnemonic from physical coin flips.

Python 3.8+ standard library only. No network. No disk writes.

RUN THIS AIRGAPPED. A seed phrase typed into a networked machine is a
seed phrase you should assume is compromised.

Usage:
    python3 bitflip.py                   # interactive, guided entry
    python3 bitflip.py HTTHHTTH...       # the whole flip string as an argument

Verification:
    Re-derive the same flips on a second, independent implementation
    (SeedSigner, Coldcard, an offline copy of Ian Coleman's BIP39 tool)
    and confirm the words AND the xprv match. One tool agreeing with
    itself proves nothing.
"""

import argparse
import hashlib
import hmac
import math
import os
import sys
import time
import unicodedata

WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

_WORDLIST_BLOB = """\
abandon ability able about above absent absorb abstract
absurd abuse access accident account accuse achieve acid
acoustic acquire across act action actor actress actual
adapt add addict address adjust admit adult advance
advice aerobic affair afford afraid again age agent
agree ahead aim air airport aisle alarm album
alcohol alert alien all alley allow almost alone
alpha already also alter always amateur amazing among
amount amused analyst anchor ancient anger angle angry
animal ankle announce annual another answer antenna antique
anxiety any apart apology appear apple approve april
arch arctic area arena argue arm armed armor
army around arrange arrest arrive arrow art artefact
artist artwork ask aspect assault asset assist assume
asthma athlete atom attack attend attitude attract auction
audit august aunt author auto autumn average avocado
avoid awake aware away awesome awful awkward axis
baby bachelor bacon badge bag balance balcony ball
bamboo banana banner bar barely bargain barrel base
basic basket battle beach bean beauty because become
beef before begin behave behind believe below belt
bench benefit best betray better between beyond bicycle
bid bike bind biology bird birth bitter black
blade blame blanket blast bleak bless blind blood
blossom blouse blue blur blush board boat body
boil bomb bone bonus book boost border boring
borrow boss bottom bounce box boy bracket brain
brand brass brave bread breeze brick bridge brief
bright bring brisk broccoli broken bronze broom brother
brown brush bubble buddy budget buffalo build bulb
bulk bullet bundle bunker burden burger burst bus
business busy butter buyer buzz cabbage cabin cable
cactus cage cake call calm camera camp can
canal cancel candy cannon canoe canvas canyon capable
capital captain car carbon card cargo carpet carry
cart case cash casino castle casual cat catalog
catch category cattle caught cause caution cave ceiling
celery cement census century cereal certain chair chalk
champion change chaos chapter charge chase chat cheap
check cheese chef cherry chest chicken chief child
chimney choice choose chronic chuckle chunk churn cigar
cinnamon circle citizen city civil claim clap clarify
claw clay clean clerk clever click client cliff
climb clinic clip clock clog close cloth cloud
clown club clump cluster clutch coach coast coconut
code coffee coil coin collect color column combine
come comfort comic common company concert conduct confirm
congress connect consider control convince cook cool copper
copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle
craft cram crane crash crater crawl crazy cream
credit creek crew cricket crime crisp critic crop
cross crouch crowd crucial cruel cruise crumble crunch
crush cry crystal cube culture cup cupboard curious
current curtain curve cushion custom cute cycle dad
damage damp dance danger daring dash daughter dawn
day deal debate debris decade december decide decline
decorate decrease deer defense define defy degree delay
deliver demand demise denial dentist deny depart depend
deposit depth deputy derive describe desert design desk
despair destroy detail detect develop device devote diagram
dial diamond diary dice diesel diet differ digital
dignity dilemma dinner dinosaur direct dirt disagree discover
disease dish dismiss disorder display distance divert divide
divorce dizzy doctor document dog doll dolphin domain
donate donkey donor door dose double dove draft
dragon drama drastic draw dream dress drift drill
drink drip drive drop drum dry duck dumb
dune during dust dutch duty dwarf dynamic eager
eagle early earn earth easily east easy echo
ecology economy edge edit educate effort egg eight
either elbow elder electric elegant element elephant elevator
elite else embark embody embrace emerge emotion employ
empower empty enable enact end endless endorse enemy
energy enforce engage engine enhance enjoy enlist enough
enrich enroll ensure enter entire entry envelope episode
equal equip era erase erode erosion error erupt
escape essay essence estate eternal ethics evidence evil
evoke evolve exact example excess exchange excite exclude
excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend
extra eye eyebrow fabric face faculty fade faint
faith fall false fame family famous fan fancy
fantasy farm fashion fat fatal father fatigue fault
favorite feature february federal fee feed feel female
fence festival fetch fever few fiber fiction field
figure file film filter final find fine finger
finish fire firm first fiscal fish fit fitness
fix flag flame flash flat flavor flee flight
flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot
force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend
fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy
gallery game gap garage garbage garden garlic garment
gas gasp gate gather gauge gaze general genius
genre gentle genuine gesture ghost giant gift giggle
ginger giraffe girl give glad glance glare glass
glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip
govern gown grab grace grain grant grape grass
gravity great green grid grief grit grocery group
grow grunt guard guess guide guilt guitar gun
gym habit hair half hammer hamster hand happy
harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet
help hen hero hidden high hill hint hip
hire history hobby hockey hold hole holiday hollow
home honey hood hope horn horror horse hospital
host hotel hour hover hub huge human humble
humor hundred hungry hunt hurdle hurry hurt husband
hybrid ice icon idea identify idle ignore ill
illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate
indoor industry infant inflict inform inhale inherit initial
inject injury inmate inner innocent input inquiry insane
insect inside inspire install intact interest into invest
invite involve iron island isolate issue item ivory
jacket jaguar jar jazz jealous jeans jelly jewel
job join joke journey joy judge juice jump
jungle junior junk just kangaroo keen keep ketchup
key kick kid kidney kind kingdom kiss kit
kitchen kite kitten kiwi knee knife knock know
lab label labor ladder lady lake lamp language
laptop large later latin laugh laundry lava law
lawn lawsuit layer lazy leader leaf learn leave
lecture left leg legal legend leisure lemon lend
length lens leopard lesson letter level liar liberty
library license life lift light like limb limit
link lion liquid list little live lizard load
loan lobster local lock logic lonely long loop
lottery loud lounge love loyal lucky luggage lumber
lunar lunch luxury lyrics machine mad magic magnet
maid mail main major make mammal man manage
mandate mango mansion manual maple marble march margin
marine market marriage mask mass master match material
math matrix matter maximum maze meadow mean measure
meat mechanic medal media melody melt member memory
mention menu mercy merge merit merry mesh message
metal method middle midnight milk million mimic mind
minimum minor minute miracle mirror misery miss mistake
mix mixed mixture mobile model modify mom moment
monitor monkey monster month moon moral more morning
mosquito mother motion motor mountain mouse move movie
much muffin mule multiply muscle museum mushroom music
must mutual myself mystery myth naive name napkin
narrow nasty nation nature near neck need negative
neglect neither nephew nerve nest net network neutral
never news next nice night noble noise nominee
noodle normal north nose notable note nothing notice
novel now nuclear number nurse nut oak obey
object oblige obscure observe obtain obvious occur ocean
october odor off offer office often oil okay
old olive olympic omit once one onion online
only open opera opinion oppose option orange orbit
orchard order ordinary organ orient original orphan ostrich
other outdoor outer output outside oval oven over
own owner oxygen oyster ozone pact paddle page
pair palace palm panda panel panic panther paper
parade parent park parrot party pass patch path
patient patrol pattern pause pave payment peace peanut
pear peasant pelican pen penalty pencil people pepper
perfect permit person pet phone photo phrase physical
piano picnic picture piece pig pigeon pill pilot
pink pioneer pipe pistol pitch pizza place planet
plastic plate play please pledge pluck plug plunge
poem poet point polar pole police pond pony
pool popular portion position possible post potato pottery
poverty powder power practice praise predict prefer prepare
present pretty prevent price pride primary print priority
prison private prize problem process produce profit program
project promote proof property prosper protect proud provide
public pudding pull pulp pulse pumpkin punch pupil
puppy purchase purity purpose purse push put puzzle
pyramid quality quantum quarter question quick quit quiz
quote rabbit raccoon race rack radar radio rail
rain raise rally ramp ranch random range rapid
rare rate rather raven raw razor ready real
reason rebel rebuild recall receive recipe record recycle
reduce reflect reform refuse region regret regular reject
relax release relief rely remain remember remind remove
render renew rent reopen repair repeat replace report
require rescue resemble resist resource response result retire
retreat return reunion reveal review reward rhythm rib
ribbon rice rich ride ridge rifle right rigid
ring riot ripple risk ritual rival river road
roast robot robust rocket romance roof rookie room
rose rotate rough round route royal rubber rude
rug rule run runway rural sad saddle sadness
safe sail salad salmon salon salt salute same
sample sand satisfy satoshi sauce sausage save say
scale scan scare scatter scene scheme school science
scissors scorpion scout scrap screen script scrub sea
search season seat second secret section security seed
seek segment select sell seminar senior sense sentence
series service session settle setup seven shadow shaft
shallow share shed shell sheriff shield shift shine
ship shiver shock shoe shoot shop short shoulder
shove shrimp shrug shuffle shy sibling sick side
siege sight sign silent silk silly silver similar
simple since sing siren sister situate six size
skate sketch ski skill skin skirt skull slab
slam sleep slender slice slide slight slim slogan
slot slow slush small smart smile smoke smooth
snack snake snap sniff snow soap soccer social
sock soda soft solar soldier solid solution solve
someone song soon sorry sort soul sound soup
source south space spare spatial spawn speak special
speed spell spend sphere spice spider spike spin
spirit split spoil sponsor spoon sport spot spray
spread spring spy square squeeze squirrel stable stadium
staff stage stairs stamp stand start state stay
steak steel stem step stereo stick still sting
stock stomach stone stool story stove strategy street
strike strong struggle student stuff stumble style subject
submit subway success such sudden suffer sugar suggest
suit summer sun sunny sunset super supply supreme
sure surface surge surprise surround survey suspect sustain
swallow swamp swap swarm swear sweet swift swim
swing switch sword symbol symptom syrup system table
tackle tag tail talent talk tank tape target
task taste tattoo taxi teach team tell ten
tenant tennis tent term test text thank that
theme then theory there they thing this thought
three thrive throw thumb thunder ticket tide tiger
tilt timber time tiny tip tired tissue title
toast tobacco today toddler toe together toilet token
tomato tomorrow tone tongue tonight tool tooth top
topic topple torch tornado tortoise toss total tourist
toward tower town toy track trade traffic tragic
train transfer trap trash travel tray treat tree
trend trial tribe trick trigger trim trip trophy
trouble truck true truly trumpet trust truth try
tube tuition tumble tuna tunnel turkey turn turtle
twelve twenty twice twin twist two type typical
ugly umbrella unable unaware uncle uncover under undo
unfair unfold unhappy uniform unique unit universe unknown
unlock until unusual unveil update upgrade uphold upon
upper upset urban urge usage use used useful
useless usual utility vacant vacuum vague valid valley
valve van vanish vapor various vast vault vehicle
velvet vendor venture venue verb verify version very
vessel veteran viable vibrant vicious victory video view
village vintage violin virtual virus visa visit visual
vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want
warfare warm warrior wash wasp waste water wave
way wealth weapon wear weasel weather web wedding
weekend weird welcome west wet whale what wheat
wheel when where whip whisper wide width wife
wild will win window wine wing wink winner
winter wire wisdom wise wish witness wolf woman
wonder wood wool word work world worry worth
wrap wreck wrestle wrist write wrong yard year
yellow you young youth zebra zero zone zoo
"""

def load_wordlist():
    words = _WORDLIST_BLOB.split()
    if len(words) != 2048:
        sys.exit("FATAL: embedded wordlist has %d entries, expected 2048" % len(words))
    digest = hashlib.sha256(("\n".join(words) + "\n").encode()).hexdigest()
    if digest != WORDLIST_SHA256:
        sys.exit(
            "FATAL: embedded wordlist failed integrity check.\n"
            "  expected %s\n  got      %s\n"
            "This file has been altered or corrupted. Do not use it." % (WORDLIST_SHA256, digest)
        )
    return words


# ---------------------------------------------------------------------------
# RIPEMD-160. hashlib usually cannot provide this on OpenSSL 3.x, where it
# lives in the legacy provider and is disabled by default. Pure-Python
# fallback below so the fingerprint check works everywhere.
# ---------------------------------------------------------------------------

_RL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_RR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
_M32 = 0xFFFFFFFF


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _ripemd160_py(data):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytearray(data)
    bitlen = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += (bitlen & (2 ** 64 - 1)).to_bytes(8, "little")

    for off in range(0, len(msg), 64):
        block = msg[off:off + 64]
        x = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = (_rol((al + _f(j, bl, cl, dl) + x[_RL[j]] + _KL[j // 16]) & _M32, _SL[j]) + el) & _M32
            al, bl, cl, dl, el = el, t, bl, _rol(cl, 10), dl
            t = (_rol((ar + _f(79 - j, br, cr, dr) + x[_RR[j]] + _KR[j // 16]) & _M32, _SR[j]) + er) & _M32
            ar, br, cr, dr, er = er, t, br, _rol(cr, 10), dr
        h = [
            (h[1] + cl + dr) & _M32,
            (h[2] + dl + er) & _M32,
            (h[3] + el + ar) & _M32,
            (h[4] + al + br) & _M32,
            (h[0] + bl + cr) & _M32,
        ]
    return b"".join(v.to_bytes(4, "little") for v in h)


def ripemd160(data):
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):
        return _ripemd160_py(data)


def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())


# ---------------------------------------------------------------------------
# Minimal secp256k1, only enough to turn a private key into a compressed
# public key so we can show a BIP32 master fingerprint for cross-checking.
# ---------------------------------------------------------------------------

_P = 2 ** 256 - 2 ** 32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _pt_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1) * pow(2 * y1, _P - 2, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _P - 2, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)


def compressed_pubkey(priv_bytes):
    k = int.from_bytes(priv_bytes, "big")
    if not 0 < k < _N:
        raise ValueError("private key out of range")
    r, addend = None, (_GX, _GY)
    while k:
        if k & 1:
            r = _pt_add(r, addend)
        addend = _pt_add(addend, addend)
        k >>= 1
    x, y = r
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# BIP39 / BIP32
# ---------------------------------------------------------------------------


def entropy_to_mnemonic(entropy, words):
    ent = len(entropy) * 8
    if ent not in (128, 160, 192, 224, 256):
        raise ValueError("entropy must be 128-256 bits in 32-bit steps")
    checksum_len = ent // 32
    checksum = hashlib.sha256(entropy).digest()
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(ent)
    bits += bin(checksum[0])[2:].zfill(8)[:checksum_len]
    return [words[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11)]


def mnemonic_to_seed(mnemonic, passphrase=""):
    m = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", m, salt, 2048, 64)


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    # Each leading zero byte is one leading '1'.
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def master_key(seed):
    """BIP32 master key: (private key, chain code) from the BIP39 seed."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    priv, chain = I[:32], I[32:]
    if not 0 < int.from_bytes(priv, "big") < _N:
        # Astronomically unlikely; BIP32 says reject rather than fudge it.
        raise ValueError("invalid master key for this seed")
    return priv, chain


def master_fingerprint(seed):
    priv, _ = master_key(seed)
    return hash160(compressed_pubkey(priv))[:4].hex()


def master_xprv(seed):
    """Serialized BIP32 master private key -- the importable `xprv...` form."""
    priv, chain = master_key(seed)
    payload = (
        bytes.fromhex("0488ADE4")   # mainnet private version
        + b"\x00"                   # depth 0: this is the master
        + b"\x00" * 4               # no parent, so no parent fingerprint
        + b"\x00" * 4               # child number 0
        + chain
        + b"\x00" + priv            # private keys are left-padded to 33 bytes
    )
    return b58check(payload)


# ---------------------------------------------------------------------------
# Flip input
# ---------------------------------------------------------------------------

_MAP = {"h": "1", "H": "1", "1": "1", "t": "0", "T": "0", "0": "0"}


def normalize(raw):
    out = []
    for ch in raw:
        if ch.isspace() or ch in "-_,.|":
            continue
        if ch not in _MAP:
            raise ValueError("bad character %r -- use H/T or 1/0 only" % ch)
        out.append(_MAP[ch])
    return "".join(out)


def ansi_ok():
    """True only if we can safely move the cursor back up a line."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            handle = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not k.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(k.SetConsoleMode(handle, mode.value | 0x0004))
        except Exception:
            return False
    return os.environ.get("TERM", "") not in ("", "dumb")


# ---------------------------------------------------------------------------
# One way to produce a bit without a coin, and it is still your hand that
# produces it. Pressing r takes the moment your finger arrived and keeps one
# bit of it. That is real physical entropy from outside the computer -- but
# unlike a coin it is measured by this machine's clock and delivered by its
# scheduler, so it is only as unpredictable as your typing is irregular. The
# accounting printed with the seed keeps the two apart in bits and never
# pretends a tossed bit is a flipped one.
#
# There is deliberately no option to fill a group from os.urandom. This file
# never calls it, and never calls any RNG: a seed it produces is made of coin
# flips and keystrokes, nothing else.
#
# What this also deliberately does NOT do is run a statistical test on its own
# output. Hashing does not create entropy: SHA-256 of a 20-bit source still has
# 20 bits of min-entropy, and it still passes monobit, chi-square, dieharder
# and every compressor. Measured here: a held-down key yields 0.87-0.92 bits of
# parity min-entropy per press -- statistically perfect, and worthless, because
# the user made one decision rather than 256. Against the only failure that
# matters a test has no power, and printing a passing result would manufacture
# the false confidence this file exists to refuse. The guards below are
# structural instead: they check that the keypresses actually happened.
# ---------------------------------------------------------------------------

_TOSS_KEYS = "rR"


def clock_quantum(samples=20000):
    """The smallest step this machine's clock actually moves in, in ns.

    This is the check the whole "r" mode stands on. perf_counter_ns reports
    nanoseconds everywhere, but Windows QPC is typically a 10 MHz counter, so
    every timestamp it returns is a multiple of 100 and the low bit is a
    CONSTANT ZERO. Taking t & 1 there makes every toss come out tails, with a
    valid BIP39 checksum that every wallet accepts -- the exact shape of failure
    this file exists to prevent. Dividing by the measured step instead of
    assuming 1 keeps the parity uniform on every clock: measured 0.98-0.99 bits
    per toss from a 1 ns tick all the way out to a 15.6 ms one.

    This can UNDER-estimate, on any clock whose tick is not a whole number of
    nanoseconds. Apple's M-series timebase is 125/3, a 41.67 ns tick, so
    successive deltas come back 41 and 42 and their gcd is 1 -- the real
    granularity is 42x coarser than this reports. The same holds on a Raspberry
    Pi, on most ARM64, on HPET (69.84 ns) and on the ACPI PM timer (279.37 ns).
    That is safe here: under-estimating only means dividing by too little, and
    the low bit of the result stays alive because the steps still have gcd 1.

    It can also OVER-estimate. The gcd of the steps a probe happened to observe
    is a multiple of the real tick, not the tick itself: a loop advancing by
    exactly k ticks every iteration would report k times the truth. That needs a
    probe with no jitter of its own, which is not a thing -- 20000 reads here
    produce 266 distinct deltas spanning 55-266 ns, and a single nanosecond of
    loop jitter collapses the gcd within a handful of samples. It is harmless
    when it does happen: dividing by a multiple of the tick still leaves the
    delivery jitter spanning thousands of quanta, and an over-estimate large
    enough to matter lands above _MAX_QUANTUM_NS, where r switches off rather
    than degrades.

    The direction that would actually be dangerous is reporting a quantum whose
    low bit is already dead, and that one is impossible by construction rather
    than by luck. If this returns g, then g divides every step the clock was
    seen to take, so t // g advances in steps whose gcd is 1 and its low bit
    cannot be constant. That invariant is what rules out the constant-tails
    failure -- not any claim about which side of the true tick g falls on.

    20000 samples, not 2000, because the probe has to last long enough to see
    the tick it is trying to reject. 2000 reads span about 130 us, so a clock
    coarser than that never moves during the probe at all; 20000 span 1.7 ms
    and register 140 movements at a 10 us tick.
    """
    return _quantum_of([time.perf_counter_ns() for _ in range(samples)])


def _quantum_of(ts):
    """gcd of the steps a clock actually took, or 0 if it never took one.

    Zero means "unmeasurable", and it must stay zero. An earlier version of
    this ended `return g or 1`, which turned "this clock is too coarse to
    measure" into "this clock is perfect" -- the single most dangerous value,
    and one that sails through every threshold downstream. The guard against
    coarse clocks was defeated by coarse clocks.
    """
    g = 0
    for a, b in zip(ts, ts[1:]):
        if b > a:
            g = math.gcd(g, b - a)
    return g


def _toss_bit(t_ns, quantum):
    """One bit from the moment your finger arrived.

    Three deliberate choices, each measured rather than guessed:

    The ABSOLUTE timestamp, not the gap since the last key. Subtraction mod 2
    is XOR, so the parity of a gap is just the parities of its two endpoints
    XORed together -- it cannot hold more entropy than the endpoints do, and
    verified on 27,000 real keypresses it never once differed. What it does do
    is whiten: against a source biased to P(1)=0.8 it reports 0.55 bits where
    the truth is 0.32, overstating by 73%. A whitener wearing a source's
    clothes is the last thing this file needs.

    Divided by the measured tick, not by 1. On a 100 ns clock every raw
    timestamp is a multiple of 100, so its low bit is a constant and every toss
    comes out tails -- with a valid checksum that every wallet accepts.

    The lowest bit of the tick count, and not a popcount of sixteen of them.
    Both measure the same on real keypresses -- 0.9805 and 0.9874 against an
    ideal source's 0.9833 at that sample size, which is to say both are at the
    ceiling and the difference is noise. So the tiebreak is how they FAIL, and
    there they are opposites. The low bit is provably alive: if quantum is the
    gcd of the steps this clock takes, then t // quantum advances in steps whose
    gcd is 1, so the low bit cannot be constant. Where that premise breaks the
    breakage is deafening -- every toss comes out tails and the tool prints
    "abandon abandon ... art". A popcount in the same situation emits beautifully
    balanced bits that pass every test while being worth nothing. Folding bits
    together is whitening, and whitening a dead source is exactly how this file
    would come to hand somebody a valid-checksum seed that is already spent.
    """
    return "1" if (t_ns // quantum) & 1 else "0"


_MAX_QUANTUM_NS = 10_000       # 10 us. Coarser and the bits stop being
                               #   unpredictable while still looking balanced,
                               #   and the probe itself stops being able to
                               #   measure the tick it is meant to reject.
_DEBOUNCE_NS = 100_000_000     # 100 ms of silence required before an r counts.
                               #   Above every autorepeat rate in the wild:
                               #   Windows 30 Hz (33 ms), X11 25 Hz (40 ms),
                               #   macOS 11 Hz (90 ms). Below a deliberate
                               #   press, which is 3-8 Hz.
_HINT = "   too fast, press r slowly"
# Prompt (15) + the widest group (11) + the hint. Every live redraw is padded to
# this, so one line can never leave a fragment of a longer one behind it.
_LINE_WIDTH = 15 + 11 + len(_HINT)


class FlipGuard:
    """Decides which keypresses this program is willing to call flips.

    One rule, a debounce, and the subtlety is what it debounces AGAINST.
    Measuring from the last ACCEPTED press does not work: a key repeating every
    33 ms against a 50 ms debounce simply has every other repeat accepted,
    yielding a decimated 15 Hz stream just as much the scheduler's as the one it
    came from. Measuring from the last press of ANY key, accepted or not, kills
    it outright -- while a key is down there is never 100 ms of silence in front
    of a press, so not one bit is taken and the group stops filling. The same
    disposes of a paste, whose characters arrive microseconds apart.

    There is deliberately no check for even RHYTHM, and the arithmetic is why.
    A version of this file rejected ten presses falling within 10% of each
    other, on the theory that a metronome meant a macro. But 10% of a 150 ms gap
    is 15 million nanoseconds, and the low bit of the tick count needs a few
    nanoseconds of spread to be uniform -- so it was throwing away bits with a
    million times the variation they required. Measured, a metronome pressing at
    exactly 120 ms, spin-timed so the press instant is known to the nanosecond,
    still yields 0.9564 bits per press against an ideal source's 0.9559. There
    is nothing there to catch. Meanwhile a human tapping one key steadily trips
    it, and the cost of that is a discarded group. Held keys and pastes are real
    and are handled below; even rhythm was not.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.last_key = None       # ANY key, whether or not it earned a bit

    def feed(self, t_ns, chunk_len, is_toss):
        """Called once for EVERY keystroke. True only if this one earned a bit.

        One call rather than an ask-then-tell pair, because the ordering is the
        whole mechanism and a two-call version invites comparing a press against
        itself -- which silently means nothing is ever accepted.

        Every keystroke updates the clock, not just r: holding r down inside a
        group whose other bits you typed still has to earn nothing, and a burst
        of anything at all is evidence that what follows was queued, not made.
        """
        prev, self.last_key = self.last_key, t_ns
        if not is_toss:
            return False
        # A multi-byte read is refused structurally rather than by timing: the
        # kernel handed over several characters at once, so they were queued
        # before we ever looked. (A pasted run of H/T never reaches here -- that
        # is a paper record being transcribed. A pasted r is not the same thing.)
        if chunk_len > 1:
            return False
        return prev is None or t_ns - prev >= _DEBOUNCE_NS


def keys_available():
    """True only where single keypresses can be read AND timed meaningfully."""
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return False
    except Exception:
        return False              # sys.stdin is None under pythonw
    if os.environ.get("SSH_TTY") or os.environ.get("SSH_CONNECTION"):
        # Over ssh these timestamps measure packet arrival, not your hand, and
        # every keystroke becomes an individually timed packet on the wire.
        # This tool is supposed to be airgapped anyway.
        return False
    try:
        if os.name == "nt":
            import msvcrt                                      # noqa: F401
            return True
        import termios
        termios.tcgetattr(sys.stdin.fileno())
        return True
    except Exception:
        return False              # no termios, or no fileno (IDE console)


class KeyReader:
    """Single keypresses with their arrival times.

    cbreak, not raw: ISIG stays on, so Ctrl-C is still generated by the tty
    driver rather than by an if-statement of ours. In a program that puts a
    seed phrase on screen, "Ctrl-C always works" belongs in the kernel.

    tty.setcbreak is deliberately not used: through Python 3.11 it edits the
    caller's control-character list in place and returns None, and this file
    supports 3.8. Setting the flags here also shows exactly which bits change.
    """

    def __init__(self):
        self._saved = None
        self._buf = []
        self._buf_t = 0
        self._buf_n = 1

    def __enter__(self):
        if os.name == "nt":
            import msvcrt
            self._msvcrt = msvcrt
            return self
        import signal
        import termios
        self._signal, self._termios = signal, termios
        self._fd = sys.stdin.fileno()
        self._saved = termios.tcgetattr(self._fd)
        mode = termios.tcgetattr(self._fd)     # a second, independent copy
        mode[3] &= ~(termios.ECHO | termios.ICANON)
        mode[3] |= termios.ISIG
        mode[6][termios.VMIN] = 1
        mode[6][termios.VTIME] = 0
        self._cbreak = mode
        # TCSAFLUSH, not TCSANOW: discard anything typed before this instant, so
        # keys pressed ahead of the prompt can never be counted as flips.
        termios.tcsetattr(self._fd, termios.TCSAFLUSH, mode)
        self._prev_tstp = signal.signal(signal.SIGTSTP, self._suspend)
        self._prev_cont = signal.signal(signal.SIGCONT, self._resume)
        return self

    def __exit__(self, *exc):
        self.restore()
        return False                           # never swallow KeyboardInterrupt

    def _set(self, mode):
        try:
            self._termios.tcsetattr(self._fd, self._termios.TCSADRAIN, mode)
        except Exception:
            pass      # terminal already hung up; must not mask the real error

    def restore(self):
        if self._saved is None:
            return
        # Uninstall the handlers first: a SIGTSTP arriving after _saved is
        # cleared would reach _suspend with nothing left to restore to.
        self._signal.signal(self._signal.SIGTSTP, self._prev_tstp)
        self._signal.signal(self._signal.SIGCONT, self._prev_cont)
        saved, self._saved = self._saved, None
        self._set(saved)

    def _suspend(self, sig, frame):            # Ctrl-Z: hand the tty back first
        self._set(self._saved)
        self._signal.signal(self._signal.SIGTSTP, self._signal.SIG_DFL)
        os.kill(os.getpid(), self._signal.SIGTSTP)

    def _resume(self, sig, frame):             # fg: take it back
        self._signal.signal(self._signal.SIGTSTP, self._suspend)
        if self._saved is not None:
            self._set(self._cbreak)

    def key(self):
        """(codepoint, arrival ns, how many bytes arrived in that one read)."""
        if os.name == "nt":
            ch = self._msvcrt.getwch()
            t = time.perf_counter_ns()
            if ch in ("\x00", "\xe0"):         # arrow/function key: eat the code
                self._msvcrt.getwch()
                return 0, t, 1
            if ch == "\x03":                   # getwch never raises on Ctrl-C
                raise KeyboardInterrupt
            if ch == "\x04":
                raise EOFError
            return ord(ch), t, 1
        if not self._buf:
            chunk = os.read(self._fd, 64)
            t = time.perf_counter_ns()         # first statement after the read
            if not chunk:
                raise EOFError
            self._buf, self._buf_t, self._buf_n = list(chunk), t, len(chunk)
        c = self._buf.pop(0)
        if c == 4 and self._buf_n == 1:        # ICANON is off, so Ctrl-D is a byte
            raise EOFError
        return c, self._buf_t, self._buf_n


def prompt_bits(need, label):
    prompt = "  %-11s: " % label
    while True:
        try:
            raw = input(prompt)
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nAborted. Nothing was saved.")
        try:
            bits = normalize(raw)
        except ValueError as e:
            print("    %s" % e)
            continue
        if len(bits) != need:
            print("    got %d flips, need exactly %d -- retype this group" % (len(bits), need))
            continue
        # Echo back in whichever notation they used, so the line can be
        # compared character-for-character against the paper record.
        if any(c in "hHtT" for c in raw):
            shown = bits.replace("1", "H").replace("0", "T")
        else:
            shown = bits
        return bits, prompt, shown, "c" * need


def _render(bits, kinds):
    """H/T for the ones you flipped, 0/1 for the ones you tossed.

    Provenance is then visible per bit rather than per group, so a line of
    HTHT01HT says at a glance which characters your paper record is
    authoritative for. The flip string printed at the end is plain 0/1
    regardless -- that one has to be retypeable into another tool.
    """
    return "".join("HT"[b == "0"] if k == "c" else b for b, k in zip(bits, kinds))


def keypress_bits(need, label, reader, guard, quantum, tossable):
    """Collect `need` bits one keypress at a time.

    Returns (bits, prompt, shown, kinds), where kinds has one character per
    bit: "c" you typed the flip after looking at a coin, "t" tossed from the
    arrival time of an r.
    """
    prompt = "  %-11s: " % label
    bits, kinds, hint = "", "", ""
    # The guard is deliberately NOT reset per group: it carries across group
    # boundaries, so a key held down through the end of one group still earns
    # nothing at the start of the next. The pause while you read the word only
    # ever lengthens a gap, which nothing here objects to.
    #
    # Nothing in this loop can discard work. A press either counts or is
    # ignored, so the worst a stuck key or a paste can do is fail to fill the
    # group, which is visible on the line and fixes itself the moment you let go.
    while len(bits) < need:
        # Padded to a constant width rather than cleared with an escape
        # sequence, so this whole path needs no ANSI at all and a bare \r is
        # enough: no TERM sniffing, and nothing to go wrong on a terminal that
        # does not speak it.
        #
        # Underscores for the empty slots, not dots: a great many coding fonts
        # ligature "..." into a single ellipsis glyph, which turns the count of
        # remaining flips into a lie.
        sys.stdout.write("\r%-*s"
                         % (_LINE_WIDTH,
                            "%s%s%s%s" % (prompt, _render(bits, kinds),
                                          "_" * (need - len(bits)), hint)))
        sys.stdout.flush()
        try:
            c, t, n = reader.key()
        except EOFError:
            sys.exit("\nAborted. Nothing was saved.")
        # Tuples, not strings: `"" in "hH1"` is True in Python, so any
        # unprintable key -- an arrow, Escape, DEL -- would silently insert a
        # 1 bit if these were substring tests.
        ch = chr(c) if 32 <= c < 127 else ""
        is_toss = ch in tuple(_TOSS_KEYS) and tossable
        earned = guard.feed(t, n, is_toss)            # every key goes through
        hint = ""
        if c in (8, 127):                             # backspace / DEL
            bits, kinds = bits[:-1], kinds[:-1]
        elif ch in ("h", "H", "1"):
            bits, kinds = bits + "1", kinds + "c"
        elif ch in ("t", "T", "0"):
            bits, kinds = bits + "0", kinds + "c"
        elif is_toss and earned:
            bits, kinds = bits + _toss_bit(t, quantum), kinds + "t"
        elif is_toss:
            # Not an error -- the press simply does not count. Held down, the
            # group stops filling and this line is the only thing that changes.
            hint = _HINT
        # anything else is ignored: a stray key cannot spend a bit
    return bits, prompt, _render(bits, kinds), kinds


def guided_entry(ent_bits, words):
    """Enter 11 flips at a time; each full group reveals its word immediately."""
    full_groups = ent_bits // 11
    remainder = ent_bits % 11
    total = full_groups + (1 if remainder else 0)
    inline = ansi_ok()
    live = keys_available()
    quantum = clock_quantum() if live else 0
    # Zero means the probe never saw the clock move, which is a coarser failure
    # than any threshold -- it must not pass. Beyond the threshold the tick
    # approaches the spread of the delivery jitter itself and the bits stop
    # being unpredictable even while they stay perfectly balanced. Those are two
    # different numbers and the gap between them is the whole point. Measured,
    # crediting the hand with nothing so that only the delivery jitter is
    # unknown: the min-entropy CONDITIONAL on a press schedule the attacker
    # knows exactly is 0.96 bits at 10 us and 0.86 at 100 us, while the MARGINAL
    # P(1) -- the only thing a statistical test can see -- sits at 0.4997 the
    # whole way down. A test reads the second number and passes; an attacker
    # collects the first.
    #
    # A real hand never leaves it that close. Measured over a 256-press run, the
    # cadence spread is 184 ms, which is 1.8e8 quanta on a 1 ns clock, and the
    # parity bias underflows a double. The bar is set by the case where the hand
    # contributes nothing at all -- a metronome, a macro, someone tapping to a
    # beat -- because FlipGuard can prove that presses happened and cannot prove
    # that a human chose them. Delivery jitter is not what makes a deliberate
    # press unpredictable; it is the floor that holds when the presser is a
    # machine.
    #
    # Every real clock clears this by 80x or more -- x86 TSC under 1 ns, ARM64
    # 26-125 ns, Windows QPC 100 ns, paravirtualised 1 us -- and nothing real
    # lives between there and a 15.6 ms legacy tick. So the bar costs honest
    # machines nothing and refuses every machine it should.
    tossable = live and 0 < quantum <= _MAX_QUANTUM_NS
    reader = guard = None

    print("")
    print("  H or 1   heads")
    print("  T or 0   tails")
    if tossable:
        print("  r        random, from the moment you press it")
    print("")

    def echo(prompt, shown, tail):
        # One echo for every group, full or short. No provenance label: the
        # rendering already carries it per bit, H/T for a flip and 0/1 for a
        # toss, which says more than a tag on the whole group could.
        #
        # In keypress mode we never left the line, so a bare \r is enough and no
        # ANSI is involved. In line mode \033[F steps back over the line the
        # user submitted, whose width is at most prompt + 11 = 26 columns.
        if live:
            # Blank the row first, then write the finished line, so the "too
            # fast" hint cannot survive underneath it and the line that lands in
            # the scrollback carries no trailing spaces.
            line = "%s%-11s  %s" % (prompt, shown, tail)
            sys.stdout.write("\r%s\r%s\n" % (" " * _LINE_WIDTH, line))
            sys.stdout.flush()
        elif inline:
            sys.stdout.write("\033[F\033[2K%s%-11s  %s\n" % (prompt, shown, tail))
            sys.stdout.flush()
        else:
            print("    %s" % tail)

    def one_group(need, label):
        if live:
            return keypress_bits(need, label, reader, guard, quantum, tossable)
        return prompt_bits(need, label)

    bits, kinds = "", ""
    try:
        if live:
            reader = KeyReader().__enter__()
            guard = FlipGuard()
        for i in range(full_groups):
            group, prompt, shown, k = one_group(11, "group %2d/%d" % (i + 1, total))
            echo(prompt, shown, "->  %s" % words[int(group, 2)])
            bits, kinds = bits + group, kinds + k

        if remainder:
            group, prompt, shown, k = one_group(remainder, "group %2d/%d" % (total, total))
            bits, kinds = bits + group, kinds + k
            # The last word is short of a full group because the missing bits
            # are the checksum, which is a function of everything above -- so it
            # can only be named once the final flip is in, which it now is.
            echo(prompt, shown, "->  %s" % entropy_to_mnemonic(
                int(bits, 2).to_bytes(ent_bits // 8, "big"), words)[-1])
    except KeyboardInterrupt:
        if reader is not None:
            reader.restore()
        sys.exit("\nAborted. Nothing was saved.")
    finally:
        if reader is not None:
            reader.restore()
    return bits, kinds


def ask_words():
    while True:
        try:
            raw = input("\nHow many words, 12 or 24? [24]: ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nAborted. Nothing was saved.")
        if raw == "":
            return 24
        if raw in ("12", "24"):
            return int(raw)
        print("    enter 12 or 24")


# ---------------------------------------------------------------------------
# Self-check against the published BIP39 / BIP32 vectors.
#
# A wallet validates the words you type into it -- wordlist membership and the
# checksum -- so a bug in that path announces itself immediately. Nothing
# validates what comes after. A broken PBKDF2 or BIP32 still yields a phrase
# every wallet accepts, while the fingerprint and xprv printed below quietly
# describe a different wallet. These vectors are the only thing standing
# between that and your coins, so they run every time, unconditionally.
# ---------------------------------------------------------------------------

_VECTORS = [
    ("00000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
    ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank yellow",
     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"),
    ("0000000000000000000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
    ("8080808080808080808080808080808080808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"),
]

_FP_VECTOR = ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "73c5da0a")

# The entropy values above are the most famous in bitcoin, and wallets restored
# from them are watched by bots. Derived from _VECTORS rather than retyped, so
# the two can never drift apart.
_KNOWN_DEAD = frozenset(hex_ent for hex_ent, _, _ in _VECTORS)

# BIP32 test vector 1: seed 000102030405060708090a0b0c0d0e0f -> master xprv.
# Exercises the serialization and the base58check encoder end to end.
_XPRV_VECTOR = (
    "000102030405060708090a0b0c0d0e0f",
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
)


def _fail(what):
    sys.exit(
        "\nFATAL: self-check failed (%s).\n"
        "This build derives keys incorrectly. Any seed it produces would be\n"
        "wrong in ways a wallet cannot detect. Do not use its output." % what
    )


def self_check(words):
    # Only reached where hashlib lacks ripemd160, so the vectors below exercise
    # whichever path this machine happens to take and leave the other untested.
    # Check it directly, or it stays unverified until the machine that needs it
    # is the airgapped one.
    if _ripemd160_py(b"abc").hex() != "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc":
        _fail("pure-Python RIPEMD-160")
    for hex_ent, want_m, want_seed in _VECTORS:
        got_m = " ".join(entropy_to_mnemonic(bytes.fromhex(hex_ent), words))
        if got_m != want_m:
            _fail("mnemonic for entropy %s" % hex_ent)
        if mnemonic_to_seed(got_m, "TREZOR").hex() != want_seed:
            _fail("seed for entropy %s" % hex_ent)
    m, want_fp = _FP_VECTOR
    if master_fingerprint(mnemonic_to_seed(m, "")) != want_fp:
        _fail("master fingerprint")
    hex_seed, want_xprv = _XPRV_VECTOR
    if master_xprv(bytes.fromhex(hex_seed)) != want_xprv:
        _fail("BIP32 xprv")
    # Two vectors, between them fatal to every way this has been got wrong:
    # taking the raw nanosecond parity without dividing by the tick (the
    # constant-tails bug), folding a popcount over it instead, halving the
    # tick, and returning a constant either way.
    for t_ns, quantum, want in ((205, 100, "0"), (1, 1, "1")):
        if _toss_bit(t_ns, quantum) != want:
            _fail("keypress bit derivation")
    # The probe must report "unmeasurable" as 0, never as 1. A clock that never
    # moves is the coarsest one there is; calling it the finest would let every
    # threshold downstream wave it through.
    if _quantum_of([7, 7, 7, 7]) != 0 or _quantum_of([0, 40, 80, 120]) != 40:
        _fail("clock granularity probe")
    # The debounce is a pure function of arrival times, so unlike the quality of
    # the bits it CAN be pinned to vectors -- and it is the one thing standing
    # between a held-down key and a seed made of scheduler jitter. A held key at
    # 30 Hz must earn exactly one bit, the deliberate keydown that started it,
    # however long it is held; deliberate presses must earn every one.
    def _earned(gaps_ms, chunk=1):
        g, t, n = FlipGuard(), 0, 0
        for ms in gaps_ms:
            t += int(ms * 1_000_000)
            if g.feed(t, chunk, True):
                n += 1
        return n
    # Gaps are deliberately IRREGULAR here, so that only the debounce can be
    # what holds them back. With even gaps a weakened debounce would trip the
    # regularity rule instead and these vectors would pass on the wrong grounds.
    # 30 Hz is Windows autorepeat, 11 Hz is the macOS default; both must yield
    # exactly one bit -- the deliberate keydown that started the repeat.
    if _earned([33, 41, 29, 37, 45, 31, 39, 28, 43, 35]) != 1:
        _fail("keypress debounce (a held key earns bits)")
    if _earned([90, 95, 88, 92, 97, 85, 93, 89, 96, 91]) != 1:
        _fail("keypress debounce (a slow repeat earns bits)")
    if _earned([0.002] * 20, chunk=20) != 0:
        _fail("keypress burst check (a paste earns bits)")
    if _earned([300, 260, 340, 290, 310]) != 5:
        _fail("keypress debounce (deliberate presses rejected)")
    # An even rhythm above the debounce is fine and must stay fine: 10% of a
    # 150 ms gap is 15 million ns, and the bit needs a few. Nothing is thrown
    # away for being regular.
    if _earned([150] * 14) != 14:
        _fail("keypress debounce (an even rhythm is penalised)")


# ---------------------------------------------------------------------------

BANNER = """\
================================================================
  BIP39 seed from coin flips
  Run this on an airgapped machine. Nothing is written to disk.
================================================================"""


def main():
    ap = argparse.ArgumentParser(description="Derive a BIP39 mnemonic from coin flips.")
    ap.add_argument("flips", nargs="*",
                    help="the whole flip string, 128 or 256 flips; omit for guided entry")
    ap.add_argument("--passphrase", default="",
                    help="BIP39 passphrase (25th word). Empty by default.")
    args = ap.parse_args()

    words = load_wordlist()
    self_check(words)
    print(BANNER)

    if args.flips:
        try:
            bits = normalize("".join(args.flips))
        except ValueError as e:
            sys.exit(str(e))
        if len(bits) not in (128, 256):
            sys.exit("Got %d flips, need 128 (12 words) or 256 (24 words)." % len(bits))
        ent_bits = len(bits)
        kinds = "c" * ent_bits
        n_words = 12 if ent_bits == 128 else 24
        print("\n%d flips -> %d bits of entropy -> %d words."
              % (ent_bits, ent_bits, n_words))
    else:
        n_words = ask_words()
        ent_bits = n_words * 11 - n_words * 11 // 33
        print("\n%d words -> %d bits of entropy -> %d coin flips."
              % (n_words, ent_bits, ent_bits))
        bits, kinds = guided_entry(ent_bits, words)

    # A group that came back short would to_bytes() into a perfectly clean
    # 32 bytes with a zero high byte -- no exception, valid checksum, silently
    # weaker seed. Verified: int("1"*248, 2).to_bytes(32, "big") does not raise.
    if len(bits) != ent_bits or len(kinds) != ent_bits:
        _fail("entropy length")

    entropy = int(bits, 2).to_bytes(ent_bits // 8, "big")

    # NOT an entropy score. No such score is possible here and this file will
    # never print one: at 256 samples the estimators cannot tell a live seed
    # from a dead one. Measured with SP 800-90B's most generous estimator,
    # os.urandom scores 189 of 256, sha256(counter) -- worth exactly nothing --
    # scores 168, and a genuinely biased coin scores 116. A number that ranks a
    # dead source above a weak-but-real one is worse than no number at all.
    #
    # What IS decidable is exact equality against the few entropy values known
    # to be dead: the published BIP39 vectors, which have repeatedly received
    # and instantly lost real money, and the single-repeated-byte patterns that
    # a broken input path produces. A real coin lands on one of these with
    # probability about 2^-248, so this can only ever fire on a bug.
    if len(set(entropy)) == 1 or entropy.hex() in _KNOWN_DEAD:
        sys.exit(
            "\nFATAL: this entropy is a published test vector or a constant\n"
            "byte, so the wallet it derives is public and is emptied within\n"
            "seconds of being funded. Something upstream is broken -- do not\n"
            "use these words, and check the flips you entered.")
    mnemonic_words = entropy_to_mnemonic(entropy, words)
    mnemonic = " ".join(mnemonic_words)
    seed = mnemonic_to_seed(mnemonic, args.passphrase)

    # Guided entry already named every word as its group was completed, so
    # printing them again is just the same secret on screen twice. From an
    # argument there was no such running commentary, and this is the only place
    # the words appear at all.
    if args.flips:
        print("\n" + "=" * 64)
        print("  YOUR SEED PHRASE -- anyone who sees this owns your coins")
        print("=" * 64 + "\n")
        rows = len(mnemonic_words) // 3
        for r in range(rows):
            cells = ["%2d. %-8s" % (c * rows + r + 1, mnemonic_words[c * rows + r])
                     for c in range(3)]
            print("   " + "   ".join(cells).rstrip())

    priv, chain = master_key(seed)
    print("\n  BIP32 master private key")
    print("    xprv:       %s" % master_xprv(seed))
    print("    key (hex):  %s" % priv.hex())
    print("    chain code: %s" % chain.hex())
    if args.passphrase:
        print("\n  (everything above except the words includes your passphrase)")

    print("")

    # Launched from a file manager, the terminal is the script's parent and
    # dies with it, taking the words above with it. Hold the window open.
    if sys.stdin.isatty():
        try:
            input("  Press Enter once the words are written down. ")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    main()
