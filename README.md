# scrub

Replace sensitive strings in file content and filename. The original file is never modified — output is written as a new file with all sensitive strings removed from both the content and the filename.

**Supported formats:** `.txt`, `.pdf`

## Requirements

```bash
pip install pymupdf
```

PyMuPDF is only required for PDF files. Plain text files have no dependencies.

## Usage

```bash
python3 scrub.py <input_file> --scrub "<string>" [--scrub "<string>" ...] [options]
python3 scrub.py <input_file> --terms <terms_file> [options]
```

`--scrub` and `--terms` can be combined in the same command.

### Arguments

| Argument | Description |
|---|---|
| `input_file` | Path to the `.txt` or `.pdf` file to scrub |
| `--scrub STRING` | Sensitive string to replace (repeatable, up to any number) |
| `--terms FILE` | Path to a file with one sensitive string per line |
| `--replacement TEXT` | String to substitute in (default: `dummy`) |
| `--output-dir DIR` | Directory to write the scrubbed file (default: same as input) |

## Examples

```bash
# Scrub a single term
python3 scrub.py report.pdf --scrub "Goodyear"

# Scrub multiple terms inline
python3 scrub.py report.pdf --scrub "Goodyear" --scrub "John Smith" --scrub "secret@email.com"

# Scrub using a terms file
python3 scrub.py report.pdf --terms terms.txt

# Combine inline terms and a terms file
python3 scrub.py report.pdf --scrub "Goodyear" --terms terms.txt

# Use a custom replacement string
python3 scrub.py report.pdf --scrub "Goodyear" --replacement "[REDACTED]"

# Write output to a different directory
python3 scrub.py report.pdf --scrub "Goodyear" --output-dir ./scrubbed/
```

## Terms file format

One sensitive string per line. Lines starting with `#` and blank lines are ignored.

```
# terms.txt
Goodyear
John Smith
secret@email.com
```

## Output

The scrubbed file is written alongside the original (or to `--output-dir`), with all sensitive strings replaced in the filename too:

```
goodyear-john-smith-report.pdf  →  dummy-dummy-report.pdf
```

The script prints a summary on completion:

```
Wrote:                dummy-dummy-report.pdf
Terms scrubbed:       2
Content replacements: 23
Filename changed:     True
```
