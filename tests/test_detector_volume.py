#!/usr/bin/env python3
"""Detector recall/precision over generated data (fake only). Run: python3 tests/test_detector_volume.py

Thresholds follow the project stance: catching most of an ID or card number is
fine, so an ID counts as caught when at least 80% of its characters are removed.
"""

import base64
import hashlib
import ipaddress
import random
import re
import string
import uuid
from pathlib import Path

from helpers import Checker
import scrub

c = Checker("detector volume")
random.seed(7)
sc = scrub.Scrubber([], "dummy")
N = 1000


def removed_fraction(token: str) -> float:
    out, _ = sc.scrub_text(f"id {token} end")
    core = re.sub(r"\[(ID|NUM|IP)\]", "", out[3:-4]) if out.startswith("id ") and out.endswith(" end") else out
    return 1 - len(core) / len(token)


def recall(label, make, minimum, threshold=0.8):
    tokens = [make() for _ in range(N)]
    rate = sum(removed_fraction(t) >= threshold for t in tokens) / N
    c.check(rate >= minimum, f"{label}: {rate:.1%} caught (need {minimum:.0%})", repr(tokens[0]))


alnum = string.ascii_letters + string.digits
print("machine-style IDs")
for label, make in {
    "uuid4": lambda: str(uuid.uuid4()),
    "md5 hex": lambda: hashlib.md5(random.randbytes(8)).hexdigest(),
    "sha256 hex": lambda: hashlib.sha256(random.randbytes(8)).hexdigest(),
    "base64 (24 bytes)": lambda: base64.b64encode(random.randbytes(24)).decode(),
    "base64 (30 bytes)": lambda: base64.b64encode(random.randbytes(30)).decode(),
    "base64url (32 bytes)": lambda: base64.urlsafe_b64encode(random.randbytes(32)).decode().rstrip("="),
    "base62, 24 chars": lambda: "".join(random.choices(alnum, k=24)),
    "base62, 40 chars": lambda: "".join(random.choices(alnum, k=40)),
    "24-char hex (object id)": lambda: random.randbytes(12).hex(),
    "lowercase+digits, 26": lambda: "".join(random.choices(string.ascii_lowercase + string.digits, k=26)),
    "uppercase+digits, 24": lambda: "".join(random.choices(string.ascii_uppercase + string.digits, k=24)),
    "pure lowercase, 28": lambda: "".join(random.choices(string.ascii_lowercase, k=28)),
}.items():
    recall(label, make, 0.95)

print("documented non-matches")
short = ["AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)) for _ in range(N)]
c.check(all(removed_fraction(t) == 0 for t in short), "20-char keys (below --min-id-length) are left alone")
c.check(
    all(removed_fraction(str(random.randint(10**11, 10**12 - 1))) == 0 for _ in range(N)),
    "12-digit numbers are left alone",
)

print("numbers")
recall("13-19 digit numbers", lambda: str(random.randint(10**12, 10**random.randint(13, 18))), 0.99, 0.999)
recall("card, space-separated", lambda: " ".join(str(random.randint(1000, 9999)) for _ in range(4)), 0.99, 0.999)
recall("card, dash-separated", lambda: "-".join(str(random.randint(1000, 9999)) for _ in range(4)), 0.99, 0.999)

print("IP addresses")
v4 = [str(ipaddress.IPv4Address(random.getrandbits(32))) for _ in range(2000)]
missed = [t for t in v4 if t in sc.scrub_text(f"host {t} up")[0]]
c.check(not missed, f"IPv4: {2000 - len(missed)}/2000 scrubbed", str(missed[:5]))
v6 = [ipaddress.IPv6Address(random.getrandbits(random.choice([16, 32, 64, 128]))).compressed for _ in range(1000)]
missed = [t for t in v6 if t in sc.scrub_text(f"host {t} up")[0]]
c.check(len(missed) / 1000 <= 0.01, f"IPv6: {1000 - len(missed)}/1000 scrubbed", str(missed[:5]))

print("version strings must survive")
contexts = ["version {}", "v{}", "pkg=={}", "pkg>={}", "{}-beta", "{}rc1", "build {}", "release {}", "{}.5"]
wrong = []
for _ in range(2000):
    version = ".".join(str(random.randint(1, 255)) for _ in range(4))
    text = random.choice(contexts).format(version)
    if "[IP]" in sc.scrub_text(f"x {text} y")[0]:
        wrong.append(text)
c.check(not wrong, f"0 of 2000 version strings scrubbed ({len(wrong)} were)", str(wrong[:5]))

print("--keep-pci")
pci = scrub.Scrubber([], "dummy", keep_pci=True)
reqs = [".".join(str(random.randint(1, 12)) for _ in range(4)) for _ in range(500)]
reqs = [r for r in reqs if len(set(r.split("."))) > 1]
c.check(all(r in pci.scrub_text(f"req {r} ok")[0] for r in reqs), f"{len(reqs)} PCI-shaped numbers kept")
real = [f"{random.randint(13, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(500)]
c.check(all(r not in pci.scrub_text(f"host {r} up")[0] for r in real), "addresses with a part above 12 still scrubbed")

print("readable identifiers must survive")
words = [w for w in Path("/usr/share/dict/words").read_text(errors="ignore").split() if w.isalpha() and 4 <= len(w) <= 9]
kept = 0
tests = 1500
styles = [
    lambda ws: "_".join(w.lower() for w in ws),
    lambda ws: "-".join(w.lower() for w in ws),
    lambda ws: "".join(w.capitalize() for w in ws),
    lambda ws: "".join(ws).lower(),
]
for _ in range(tests):
    ident = random.choice(styles)(random.sample(words, 4))
    if len(ident) >= 24 and ident in sc.scrub_text(f"call {ident} now")[0]:
        kept += 1
    elif len(ident) < 24:
        kept += 1
c.check(kept / tests >= 0.95, f"{kept / tests:.1%} of word-built identifiers left alone (need 95%)")

print("false positives on real code")
import glob
import sys
files = [Path(p) for p in glob.glob(sys.base_prefix + "/lib/python3*/[a-z]*.py")][:300]
lines = ids = 0
for f in files:
    text = f.read_text(errors="ignore")
    lines += text.count("\n")
    ids += sum(1 for sp in sc.find_spans(text) if sp.kind == "id")
rate = ids / max(lines, 1) * 1000
c.check(lines > 20000, f"scanned {len(files)} stdlib files, {lines} lines")
c.check(rate < 1.5, f"{rate:.2f} ID hits per 1000 lines of Python (limit 1.5)")

c.finish()
