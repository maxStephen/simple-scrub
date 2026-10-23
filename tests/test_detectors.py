#!/usr/bin/env python3
"""Detector regression tests (fake data only). Run: python3 tests/test_detectors.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scrub  # noqa: E402

sc = scrub.Scrubber(["Acme Corp"], "dummy")

# (text, substrings that must be scrubbed, substrings that must survive)
cases = [
 # (text, should_be_scrubbed_substrings, should_survive_substrings)
 ("server 10.20.30.40 and 192.168.1.1:443 acme corp", ["10.20.30.40","192.168.1.1","acme corp"], []),
 ("host=10.0.0.5, gw 172.16.0.1.", ["10.0.0.5","172.16.0.1"], []),
 ("version 1.2.3.4 released", [], ["1.2.3.4"]),
 ("Build 10.0.19045.3693 ok; v2.4.1.9; pkg==3.1.4.1; >=2.0.0.1; 1.2.3.4-beta; 1.2.3.4rc1; 1.2.3.4.5; 01.02.03.04; 999.1.1.1", [], ["10.0.19045.3693","v2.4.1.9","==3.1.4.1","2.0.0.1","1.2.3.4-beta","1.2.3.4rc1","1.2.3.4.5","01.02.03.04","999.1.1.1"]),
 ("ipv6 2001:db8::8a2e:370:7334 and fe80::1 mac aa:bb:cc:dd:ee:ff time 12:30:45 std::vector", ["2001:db8::8a2e:370:7334","fe80::1"], ["aa:bb:cc:dd:ee:ff","12:30:45","std::vector"]),
 ("acct 1234567890123 card 4111 1111 1111 1111 and 4111-1111-1111-1111 short 123456789012 pi 3.14159265358979 price 99999999999999.56", ["1234567890123","4111 1111 1111 1111","4111-1111-1111-1111"], ["123456789012","3.14159265358979","99999999999999.56"]),
 ("id 550e8400-e29b-41d4-a716-446655440000 key aB3xK9mQ2zLp7WvR4tYh8NcD sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 b64 Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2Q=", ["550e8400-e29b-41d4-a716-446655440000","aB3xK9mQ2zLp7WvR4tYh8NcD","9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2Q="], []),
 ("MaximumConnectionTimeoutValue max_connection_timeout_value_seconds authentication-and-authorization-guidelines /usr/local/lib/python3/site-packages/requests https://docs.example.com/security/guidelines/authentication/overview internationalization_configuration_settings", [], ["MaximumConnectionTimeoutValue","max_connection_timeout_value_seconds","authentication-and-authorization-guidelines","/usr/local/lib/python3/site-packages/requests","/security/guidelines/authentication/overview","internationalization_configuration_settings"]),
 ("url https://api.example.com/v1/users/aB3xK9mQ2zLp7WvR4tYh8NcD/profile", ["aB3xK9mQ2zLp7WvR4tYh8NcD"], ["users"]),
 ("-------------------------------- ======================== aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa abcabcabcabcabcabcabcabcabc", [], ["--------------------------------","========================","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]),
]

failures = 0
for text, gone, kept in cases:
    out, _ = sc.scrub_text(text)
    for g in gone:
        if g in out:
            print("NOT SCRUBBED:", g)
            failures += 1
    for k in kept:
        if k not in out:
            print("WRONGLY SCRUBBED:", k, "->", out)
            failures += 1

keep = scrub.Scrubber([], "dummy", keep=["10.2.*"])
out, _ = keep.scrub_text("req 10.2.1.1 host 10.9.9.9")
if "10.2.1.1" not in out or "10.9.9.9" in out:
    print("--keep not honoured:", out)
    failures += 1

pci = scrub.Scrubber([], "dummy", keep_pci=True)
out, _ = pci.scrub_text("req 10.2.1.1 3.5.1.2 12.10.7.1 | real 10.0.0.1 192.168.1.1 8.8.8.8 1.1.1.1 13.2.1.1")
for kept in ("10.2.1.1", "3.5.1.2", "12.10.7.1"):
    if kept not in out:
        print("--keep-pci scrubbed a requirement number:", kept)
        failures += 1
for gone in ("10.0.0.1", "192.168.1.1", "8.8.8.8", "1.1.1.1", "13.2.1.1"):
    if gone in out:
        print("--keep-pci kept a real address:", gone)
        failures += 1

print("failures:", failures)
sys.exit(1 if failures else 0)
