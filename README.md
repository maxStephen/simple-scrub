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
| `--strip-metadata` | Also remove document properties, author names, EXIF, embedded files and zip timestamps |
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
python3 scrub.py matrix.pdf --keep "10.2.*" --keep "11.*"
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

A bare dotted quad with no context (`10.2.1.1`, `1.2.3.4` alone in a spreadsheet cell) is indistinguishable from an IP and **will** be scrubbed. Use `--dry-run` to see, and `--keep` to protect numbering schemes.

## Exit status and warnings

The tool exits `2` and prints a `WARNINGS` block when it knows something may have survived:

- a pattern was found in a PDF's text but its position could not be located to redact
- an image could not be decoded or OCR'd (for example, EMF/WMF/SVG graphics)
- an Office file contains embedded objects (`embeddings/`, `.bin`) that cannot be scrubbed
- one of your `--scrub` terms is still present somewhere in an Office file after scrubbing (sheet names and formulas are not rewritten, since renaming them would break the workbook)
- a PDF has annotations, form fields or embedded files that are not scrubbed

Treat a warning as "review before sharing." Exit `0` means nothing was flagged, not that OCR cannot have missed something.

## Limits

- OCR is not perfect: low-resolution, rotated or stylised text can be missed, and an ID the OCR misreads may not match. Spot-check redacted images.
- `--dry-run` prints the matched values (so you can judge them) to your terminal.
- Excel numeric cells (stored as numbers, not text) are not scrubbed by the long-number detector, and chart-cache values are not scrubbed by the detectors.
- Opaque printer settings blobs (`printerSettings*.bin`) inside Office files are left as is.
- Faces, logos and handwriting are not detected.
- Macro-enabled (`.docm`/`.xlsm`/`.pptm`), legacy (`.doc`/`.xls`/`.ppt`) and password-protected files are not supported.
- Metadata (PDF info + XMP, Office properties) is scrubbed for your named terms by default; use `--strip-metadata` to remove it entirely. Image EXIF is kept unless `--strip-metadata` is set.

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
.venv/bin/python tests/test_detectors.py
```

## Changelog

### v0.3.0

- Images are scrubbed via OCR: standalone images, images inside PDFs (including scanned pages), and images inside Word/PowerPoint/Excel files.
- New formats: `.docx`, `.pptx`, `.xlsx`, `.png`, `.jpg`, `.jpeg`, `.bmp`, `.webp`.
- Automatic detection of IP addresses, 13+ digit numbers and machine-style IDs; version strings are left intact.
- New options: `--keep`, `--no-ip`, `--no-numbers`, `--no-ids`, `--min-id-length`, `--strip-metadata`, `--dry-run`.
- Exits with status 2 and a warnings list when something may have survived scrubbing.
- Pinned `pymupdf<2`; added `requirements.txt` and detector tests.

### v0.2.0

- Updated README examples to use generic placeholder terms.
