# scrub

Replace sensitive strings and patterns in file content and filename. The original file is never modified — output is written as a new file with all sensitive material removed from both the content and the filename.

**Supported formats:** `.txt`, `.pdf`, `.docx`, `.pptx`, `.xlsx`, `.png`, `.jpg`, `.jpeg`, `.bmp`, `.webp`

Besides the strings you supply, it automatically detects and scrubs:

| Detector | What it catches | Replaced with |
|---|---|---|
| IP addresses | IPv4 (octets 0–255) and IPv6 | `[IP]` |
| Long numbers | 13+ digits, optionally split by single spaces or dashes (card/account style) | `[NUM]` |
| Machine-style IDs | 24+ character tokens of letters/digits/`-_+/` with high randomness and no dictionary words (UUIDs, hashes, API keys, base64) | `[ID]` |

**Images are scrubbed too.** Standalone images, images embedded in PDFs (including scanned pages), and images inside Word/PowerPoint/Excel files are OCR'd; any word that matches is covered with a solid black box.

## Requirements

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
brew install tesseract        # OCR engine, needed for any image work
```

Dependencies load lazily, so `.txt` files need nothing beyond Python. The detectors use `/usr/share/dict/words` (present on macOS) to avoid scrubbing readable identifiers.

PyMuPDF is pinned below 2.0: version 2.0 shifts the remaining text on a line after a redaction, which makes neighbouring words vanish under the redaction box.

## Usage

```bash
python3 scrub.py <input_file> [--scrub "<string>" ...] [--terms <terms_file>] [options]
```

Automatic detection is on by default, so `--scrub`/`--terms` are optional. `--scrub` and `--terms` can be combined.

### Arguments

| Argument | Description |
|---|---|
| `input_file` | File to scrub |
| `--scrub STRING` | Sensitive string to replace (repeatable) |
| `--terms FILE` | File with one sensitive string per line (`#` lines ignored) |
| `--replacement TEXT` | Replacement for `--scrub`/`--terms` matches (default: `dummy`) |
| `--output-dir DIR` | Where to write the scrubbed file (default: next to the input) |
| `--no-ip` / `--no-numbers` / `--no-ids` | Turn off one automatic detector |
| `--min-id-length N` | Minimum length of a machine-style ID (default: 24) |
| `--keep PATTERN` | Never auto-scrub a detected match that fits the pattern (repeatable; `*`/`?` wildcards, case-insensitive). Does not apply to `--scrub` terms |
| `--keep-pci` | Never scrub dotted numbers shaped like PCI requirement numbers (four parts, each 1–12, e.g. `10.2.1.1`, `3.5.1.2`). `10.0.0.1`, `192.168.1.1` and all-equal quads like `8.8.8.8` are still scrubbed |
| `--keep-exif` | Keep image EXIF data. Dropped by default because EXIF can embed a thumbnail of the unredacted picture |
| `--strip-metadata` | Also remove document properties, author names, ICC profiles, embedded files and zip timestamps |
| `--dry-run` | List what would be scrubbed; write nothing |

## Examples

```bash
# Preview first — always worth doing on a new kind of document
python3 scrub.py report.pdf --scrub "Acme Corp" --dry-run

# Scrub a name plus everything the detectors find
python3 scrub.py report.pdf --scrub "Acme Corp" --output-dir ./scrubbed/

# Terms file, plus wipe author/EXIF/document properties
python3 scrub.py deck.pptx --terms terms.txt --strip-metadata

# Screenshot with sensitive text
python3 scrub.py screenshot.png --scrub "Acme Corp"

# Detectors only, no named terms
python3 scrub.py notes.txt

# PCI requirement numbers like 10.2.1.1 look like IPs; protect them
python3 scrub.py matrix.pdf --keep-pci

# Or protect a specific range yourself
python3 scrub.py matrix.pdf --keep "10.2.*"
```

## Terms file format

```
# terms.txt
Acme Corp
John Smith
secret@email.com
```

## What is left alone on purpose

- **Version strings** stay intact: `version 1.2.3.4`, `v2.4.1.9`, `pkg==3.1.4.1`, `1.2.3.4-beta`, `1.2.3.4.5`, `01.02.03.04`, and anything whose octets exceed 255 (`10.0.19045.3693`).
- **Readable identifiers**, such as `MaximumConnectionTimeoutValue` or `authentication-and-authorization-guidelines`, are not treated as IDs. In a URL path only the ID-like segment is scrubbed.
- Numbers shorter than 13 digits, and decimals like `3.14159265358979`.

A bare dotted quad with no context (`10.2.1.1`, `1.2.3.4` alone in a spreadsheet cell) is indistinguishable from an IP and **will** be scrubbed. Use `--dry-run` to see (it also lists anything allow-listed), `--keep-pci` for PCI requirement numbering, and `--keep` for other schemes. `--keep-pci` can still protect a real address whose parts are all 1–12 (such as `10.1.2.3`), so check the dry-run list.

## Exit status and warnings

The tool exits `2` and prints a `WARNINGS` block when it knows something may have survived:

- a pattern was found in a PDF's text but its position could not be located to redact
- an image could not be decoded or OCR'd (for example, EMF/WMF/SVG graphics)
- an Office file contains embedded objects (`embeddings/`, `.bin`) that cannot be scrubbed
- one of your `--scrub` terms is still present somewhere in an Office file after scrubbing (sheet names and formulas are not rewritten, since renaming them would break the workbook)
- a PDF has annotations, form fields or embedded files that are not scrubbed
- **post-save check failed:** after writing a PDF the tool re-opens it and warns if any redacted text is still extractable (page text, metadata, XMP) or if the original bytes of a replaced JPEG are still in the file

Treat a warning as "review before sharing." Exit `0` means nothing was flagged, not that OCR cannot have missed something.

## Limits

- OCR is not perfect: low-resolution, rotated or stylised text can be missed, and an ID the OCR misreads may not match. Spot-check redacted images.
- `--dry-run` prints the matched values (so you can judge them) to your terminal.
- Excel numeric cells (stored as numbers, not text) are not scrubbed by the long-number detector, and chart-cache values are not scrubbed by the detectors.
- Opaque printer settings blobs (`printerSettings*.bin`) inside Office files are left as is.
- Faces, logos and handwriting are not detected.
- Macro-enabled (`.docm`/`.xlsm`/`.pptm`), legacy (`.doc`/`.xls`/`.ppt`) and password-protected files are not supported.
- Metadata (PDF info + XMP, Office properties) is scrubbed for your named terms by default; use `--strip-metadata` to remove it entirely. Image EXIF is dropped by default (see `--keep-exif`).

## Output

The scrubbed file is written alongside the original (or to `--output-dir`), with sensitive strings and patterns replaced in the filename too:

```
Acme Corp John Smith report.pdf  →  dummy dummy report.pdf
```

Summary printed on completion:

```
Wrote:                dummy dummy report.pdf
Terms scrubbed:       2
Content replacements: 23 (terms 18, IPs 2, numbers 1, IDs 2)
Filename changed:     True
```

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt     # fixture builders only
.venv/bin/python tests/run_all.py
```

| Script | Covers |
|---|---|
| `test_detectors.py` | Hand-picked detector cases, version strings, `--keep`, `--keep-pci` |
| `test_detector_volume.py` | Recall over 1,000 generated IDs per family, numbers, IPv4/IPv6; 2,000 version strings must survive; false-positive rate on stdlib code |
| `test_robustness.py` | Latin-1/UTF-8 BOM/UTF-16 text, unicode names, empty/corrupt/encrypted files, name collisions, refusing to overwrite the input |
| `test_warnings.py` | Every warning fires (embedded objects, EMF, undecodable image, term left in a sheet name or zip entry, PDF annotations/attachments) and clean files do not warn |

This is a "pretty good" suite, not a complete one. Known gaps are listed below.

## Known gaps

- **An ID that wraps across two lines in a PDF is missed silently** (neither half reaches the 24-character minimum, and nothing warns). Likely in narrow table cells.
- **Keys shorter than 24 characters** (for example a 20-character `AKIA…` access key) are not detected; lower `--min-id-length` and expect more false positives. Numbers of 12 digits or fewer are also left alone by design.
- Detector false-positive rate on code is about 2 hits per 1,000 lines (hashes in URLs, alphabet constants). Review with `--dry-run`.

## Test roadmap (not yet written)

1. **Independent leak check.** Our rescans reuse the tool's own detectors and OCR, so they share its blind spots. Add a different oracle: unzip Office files and grep every part, grep decompressed PDF streams, OCR with other settings.
2. **The original is never modified.** Hash the input before and after.
3. **`--dry-run` writes nothing.** Compare the output directory before and after.
4. **PyMuPDF drift regression.** Assert that words untouched by a multi-redaction line keep their x-positions (guards the `pymupdf<2` pin).
5. **CLI behaviour matrix.** Flag combinations, exit codes, terms-file parsing, regex characters in terms, overlapping terms.
6. **OCR on realistic images.** Small UI fonts, dark mode, low contrast, JPEG noise, rotation; measure the miss rate.
7. **Real Office features.** Headers/footers, footnotes, text boxes, tracked changes, comments, hyperlinks, charts, hidden sheets.
8. **Open outputs in real applications** (Word, Excel, PowerPoint or LibreOffice), not just python-docx/openpyxl/python-pptx, which are lenient.
9. **Scale.** Large multi-page PDFs and OCR run time.

## Changelog

### v0.4.1

- Text files keep their encoding (UTF-8, UTF-8 BOM, UTF-16, Latin-1) and line endings; previously non-UTF-8 files crashed.
- Corrupt, empty or unreadable inputs now fail with a one-line message, no traceback, and no partial output.
- Added robustness, warning-path and detector-volume tests, a test runner and `requirements-dev.txt`; documented known gaps and a test roadmap.

### v0.4.0

- `--keep-pci` protects PCI requirement numbers from the IP detector; `--dry-run` now lists allow-listed matches.
- Image EXIF is dropped by default (it can embed an unredacted thumbnail); `--keep-exif` opts back in.
- PDFs are re-opened after saving and checked for recoverable redacted text and leftover original image data.

### v0.3.0

- Images are scrubbed via OCR: standalone images, images inside PDFs (including scanned pages), and images inside Word/PowerPoint/Excel files.
- New formats: `.docx`, `.pptx`, `.xlsx`, `.png`, `.jpg`, `.jpeg`, `.bmp`, `.webp`.
- Automatic detection of IP addresses, 13+ digit numbers and machine-style IDs; version strings are left intact.
- New options: `--keep`, `--no-ip`, `--no-numbers`, `--no-ids`, `--min-id-length`, `--strip-metadata`, `--dry-run`.
- Exits with status 2 and a warnings list when something may have survived scrubbing.
- Pinned `pymupdf<2`; added `requirements.txt` and detector tests.

### v0.2.0

- Updated README examples to use generic placeholder terms.
