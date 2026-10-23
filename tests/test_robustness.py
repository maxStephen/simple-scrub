#!/usr/bin/env python3
"""Odd inputs: encodings, unicode names, corrupt/empty/encrypted files, name collisions.

Run: python3 tests/test_robustness.py   (needs requirements-dev.txt)
"""

import hashlib
import tempfile
from pathlib import Path

from helpers import Checker, run

c = Checker("robustness")


def clean_failure(label, result, out_dir, expect_in_stderr=None):
    """A bad input must fail with a message, no traceback, and leave no partial output."""
    c.check(result.returncode != 0, f"{label}: exits non-zero", result.stdout)
    c.check("Traceback" not in result.stderr, f"{label}: no traceback", result.stderr)
    if expect_in_stderr:
        c.check(expect_in_stderr in result.stderr.lower(), f"{label}: helpful message", result.stderr)
    leftovers = list(out_dir.glob("*")) if out_dir.exists() else []
    c.check(not leftovers, f"{label}: no partial output left", str(leftovers))


with tempfile.TemporaryDirectory() as tmp:
    td = Path(tmp)
    out = td / "out"
    base = ["--scrub", "Acme Corp", "--output-dir", out]

    # -- text encodings ------------------------------------------------------
    f = td / "Acme Corp empty.txt"
    f.write_bytes(b"")
    r = run(f, *base)
    c.check(r.returncode == 0 and (out / "dummy empty.txt").read_bytes() == b"", "empty .txt", r.stderr)

    f = td / "latin1.txt"
    f.write_bytes("Caf\xe9 Acme Corp 10.20.30.40\r\nline2\r\n".encode("latin-1"))
    r = run(f, *base)
    got = (out / "latin1.txt").read_bytes() if (out / "latin1.txt").exists() else b""
    c.check(
        r.returncode == 0 and got == "Caf\xe9 dummy [IP]\r\nline2\r\n".encode("latin-1"),
        "latin-1 .txt: encoding and CRLF preserved", r.stderr or repr(got),
    )

    f = td / "bom.txt"
    f.write_bytes("﻿Acme Corp résumé\n".encode("utf-8"))
    r = run(f, *base)
    got = (out / "bom.txt").read_bytes() if (out / "bom.txt").exists() else b""
    c.check(
        r.returncode == 0 and got == "﻿dummy résumé\n".encode("utf-8"),
        "utf-8 BOM .txt: BOM preserved", r.stderr or repr(got),
    )

    f = td / "utf16.txt"
    f.write_bytes("Acme Corp 10.20.30.40\n".encode("utf-16"))
    r = run(f, *base)
    got = (out / "utf16.txt").read_bytes() if (out / "utf16.txt").exists() else b""
    c.check(
        r.returncode == 0 and got.decode("utf-16", errors="replace") == "dummy [IP]\n",
        "utf-16 .txt", r.stderr or repr(got),
    )

    # -- names ----------------------------------------------------------------
    f = td / "Ácme Çorp ñ.txt"
    f.write_text("hello ácme çorp", encoding="utf-8")
    r = run(f, "--scrub", "ácme çorp", "--output-dir", out)
    c.check(
        r.returncode == 0 and (out / "dummy ñ.txt").read_text(encoding="utf-8") == "hello dummy",
        "unicode filename and case-insensitive unicode term", r.stderr,
    )

    f = td / "Acme Corp.txt"  # the whole stem is the term
    f.write_text("x Acme Corp")
    r = run(f, *base)
    c.check(r.returncode == 0 and (out / "dummy.txt").exists(), "stem that is entirely a term", r.stderr)

    # -- output collisions and the original ------------------------------------
    f = td / "Acme Corp collide.txt"
    f.write_text("Acme Corp")
    digest = hashlib.sha256(f.read_bytes()).hexdigest()
    run(f, *base)
    r = run(f, *base)
    c.check(
        r.returncode == 0 and (out / "dummy collide.txt").exists() and (out / "dummy collide-1.txt").exists(),
        "name collision gets a -1 suffix, nothing overwritten", r.stderr,
    )
    c.check(hashlib.sha256(f.read_bytes()).hexdigest() == digest, "original untouched after two runs")

    plain = td / "plain.txt"
    plain.write_text("Acme Corp")
    r = run(plain, "--scrub", "Acme Corp")  # output would equal input
    c.check(
        r.returncode != 0 and plain.read_text() == "Acme Corp" and "same as input" in r.stderr,
        "refuses to overwrite the input", r.stderr,
    )

    # -- argument errors ---------------------------------------------------------
    r = run(td / "missing.txt", "--scrub", "x")
    c.check(r.returncode != 0 and "Traceback" not in r.stderr, "missing file")
    f = td / "notes.rtf"
    f.write_text("x")
    r = run(f, "--scrub", "x")
    c.check(r.returncode != 0 and "unsupported" in r.stderr.lower(), "unsupported extension")
    f = td / "nothing.txt"
    f.write_text("x")
    r = run(f, "--no-ip", "--no-numbers", "--no-ids")
    c.check(r.returncode != 0 and "Traceback" not in r.stderr, "no terms and every detector off")

    # -- corrupt, empty and protected files -----------------------------------------
    bad_out = td / "bad_out"
    bad = [
        ("corrupt .pdf", "x.pdf", b"%PDF-1.7\nthis is not really a pdf"),
        ("empty .pdf", "e.pdf", b""),
        ("corrupt .docx", "x.docx", b"not a zip file at all"),
        ("empty .xlsx", "e.xlsx", b""),
        ("corrupt .png", "x.png", b"\x89PNG\r\n\x1a\ngarbage"),
        ("empty .jpg", "e.jpg", b""),
        ("password-protected .docx (OLE container)", "enc.docx", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 512),
    ]
    for label, name, data in bad:
        f = td / name
        f.write_bytes(data)
        clean_failure(label, run(f, "--scrub", "x", "--output-dir", bad_out), bad_out)

    import pymupdf
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "secret Acme Corp")
    enc = td / "locked.pdf"
    doc.save(str(enc), encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="user")
    clean_failure("password-protected .pdf", run(enc, *base[:2], "--output-dir", bad_out), bad_out, "password")

c.finish()
