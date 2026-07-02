#!/usr/bin/env python3
"""Scrub sensitive strings from file content and filename.

Supported formats: .txt, .pdf
Add new formats by subclassing FileHandler and registering in HANDLERS.
"""

import argparse
import re
import sys
from abc import ABC, abstractmethod
from pathlib import Path


class FileHandler(ABC):
    @abstractmethod
    def scrub(
        self,
        input_path: Path,
        output_path: Path,
        terms: list[str],
        replacement: str,
    ) -> int:
        """Write scrubbed content to output_path. Return total replacement count."""


def _scrub_str(text: str, terms: list[str], replacement: str) -> tuple[str, int]:
    count = 0
    for term in terms:
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        count += len(pattern.findall(text))
        text = pattern.sub(replacement, text)
    return text, count


def _unique_output_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def _load_terms_file(path: Path) -> list[str]:
    terms = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line)
    return terms


class TxtHandler(FileHandler):
    def scrub(self, input_path, output_path, terms, replacement):
        content = input_path.read_text()
        scrubbed, count = _scrub_str(content, terms, replacement)
        output_path.write_text(scrubbed)
        return count


class PdfHandler(FileHandler):
    def scrub(self, input_path, output_path, terms, replacement):
        try:
            import fitz  # pymupdf
        except ImportError:
            print(
                "pymupdf is required for PDF support: pip install pymupdf",
                file=sys.stderr,
            )
            sys.exit(1)

        doc = fitz.open(str(input_path))
        count = 0
        for page in doc:
            page_hit = False
            for term in terms:
                hits = page.search_for(term, quads=False)
                if not hits:
                    hits = page.search_for(term.lower(), quads=False)
                if not hits:
                    hits = page.search_for(term.upper(), quads=False)
                count += len(hits)
                for rect in hits:
                    page.add_redact_annot(rect, text=replacement)
                if hits:
                    page_hit = True
            if page_hit:
                page.apply_redactions()
        doc.save(str(output_path))
        return count


# Register handlers here to add support for new formats.
HANDLERS: dict[str, FileHandler] = {
    ".txt": TxtHandler(),
    ".pdf": PdfHandler(),
}


def main():
    supported = ", ".join(HANDLERS)
    parser = argparse.ArgumentParser(
        description=f"Replace sensitive strings in file content and filename. "
                    f"Supported formats: {supported}"
    )
    parser.add_argument("input_file", help="Path to the input file")
    parser.add_argument(
        "--scrub",
        action="append",
        dest="terms",
        metavar="STRING",
        default=[],
        help="Sensitive string to scrub (repeatable)",
    )
    parser.add_argument(
        "--terms",
        dest="terms_file",
        metavar="FILE",
        help="Path to a file with one sensitive string per line (# lines are ignored)",
    )
    parser.add_argument(
        "--replacement",
        default="dummy",
        help="Replacement string (default: dummy)",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory to write the scrubbed file (default: same as input)",
    )
    args = parser.parse_args()

    terms = list(args.terms)
    if args.terms_file:
        terms_path = Path(args.terms_file)
        if not terms_path.exists():
            print(f"Error: terms file not found: {terms_path}", file=sys.stderr)
            sys.exit(1)
        terms.extend(_load_terms_file(terms_path))

    if not terms:
        print("Error: provide at least one --scrub STRING or --terms FILE", file=sys.stderr)
        sys.exit(1)

    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    ext = input_path.suffix.lower()
    handler = HANDLERS.get(ext)
    if handler is None:
        print(
            f"Error: unsupported format '{ext}'. Supported: {supported}",
            file=sys.stderr,
        )
        sys.exit(1)

    scrubbed_name, _ = _scrub_str(input_path.name, terms, args.replacement)
    output_dir = Path(args.output_dir) if args.output_dir else input_path.parent
    output_path = output_dir / scrubbed_name

    if output_path.resolve() == input_path.resolve():
        print(
            "Error: output path is the same as input — use --output-dir to specify a different location.",
            file=sys.stderr,
        )
        sys.exit(1)

    output_path = _unique_output_path(output_path)

    count = handler.scrub(input_path, output_path, terms, args.replacement)

    print(f"Wrote:                {output_path}")
    print(f"Terms scrubbed:       {len(terms)}")
    print(f"Content replacements: {count}")
    print(f"Filename changed:     {scrubbed_name != input_path.name}")


if __name__ == "__main__":
    main()
