# simple-scrub — notes for future sessions

Python CLI that scrubs sensitive strings/patterns from txt, pdf, docx, pptx,
xlsx and images (OCR). Single file: `scrub.py`. Tests: `tests/test_detectors.py`.

## Do not upgrade pymupdf to 2.x without re-testing redaction
`requirements.txt` pins `pymupdf>=1.24,<2` on purpose. On PyMuPDF 2.0 (MuPDF
1.28), `page.apply_redactions()` shifts the text that follows a redaction to the
left. With several redactions on one line, unredacted words slide under the
neighbouring white redaction box and lose characters ("version" -> "ersion").
The text layer still reads fine, so only a visual check catches it. 1.27.x
leaves positions untouched. It happens with embedded fonts too, so it is not a
fixture quirk. If you reconsider 2.x: build a PDF with 3+ redactions on one line,
compare `page.get_text("words")` x-positions of the untouched words before and
after `apply_redactions`, and render it. Do not unpin on a passing unit test alone.

## Design stance: recall over exactness
The goal is that nothing sensitive is readable, not that every character is
matched. For machine-style IDs and card/account numbers, redacting most of the
value is fine. Do not tune regexes, lookarounds or OCR box padding to catch the
last character, and do not add complexity for OCR-misread digits. Prefer a
simple rule that over-redacts slightly. This leniency does NOT extend to
user-supplied `--scrub` terms or IP addresses; those should match fully.

## Known ambiguity
Dotted quads such as PCI requirement numbers (10.2.1.1) are valid IPv4 and cannot
be told apart by pattern. Users handle this with `--dry-run` and `--keep`.
Version strings (v1.2.3.4, 1.2.3.4-beta, >=1.2.3.4) must stay intact.

## Conventions
- Never put real client names in the repo; use "Acme Corp" in examples and tests.
- Tests use fake data only.
- Keep the README Changelog current.
