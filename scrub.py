#!/usr/bin/env python3
"""Scrub sensitive strings and patterns from file content and filename.

Supported formats: .txt, .pdf, .docx, .pptx, .xlsx, .png, .jpg, .jpeg, .bmp, .webp

Besides the strings you supply, it detects IP addresses, long numbers (13+
digits) and long machine-style IDs. Images (standalone, inside PDFs and inside
Office files) are OCR'd and matching text is blacked out.
Add new formats by subclassing FileHandler and registering in HANDLERS.
"""

import argparse
import fnmatch
import functools
import io
import ipaddress
import math
import re
import shutil
import sys
import zipfile
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

WORDS_PATH = Path("/usr/share/dict/words")

KIND_TAGS = {"ip": "[IP]", "number": "[NUM]", "id": "[ID]"}

IPV4_RE = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)")
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
NUMBER_RE = re.compile(r"(?<![\w.])\d(?:[ -]?\d){12,}(?!\w|\.\d)")
# Dotted quads that are really versions: "version 1.2.3.4", "pkg>=1.2.3.4"
VERSION_PREFIX_RE = re.compile(
    r"(?:\b(?:ver|version|rev|revision|release|build)\b\.?:?\s*|==|>=|<=|~=|!=|~>|\^|<|>)\s*$",
    re.IGNORECASE,
)


def die(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(1)


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str  # term | ip | number | id
    repl: str


class Scrubber:
    """Finds sensitive spans in text and records what was found."""

    def __init__(
        self,
        terms: list[str],
        replacement: str,
        *,
        ip: bool = True,
        numbers: bool = True,
        ids: bool = True,
        min_id_length: int = 24,
        keep: list[str] | None = None,
        dry_run: bool = False,
        strip_metadata: bool = False,
    ):
        # Longest first so "Acme Corp" wins over "Acme".
        self.terms = sorted({t for t in terms if t}, key=len, reverse=True)
        self.term_res = [re.compile(re.escape(t), re.IGNORECASE) for t in self.terms]
        self.replacement = replacement
        self.ip = ip
        self.numbers = numbers
        self.ids = ids
        self.min_id_length = min_id_length
        self.keep = [k.lower() for k in (keep or [])]
        self.dry_run = dry_run
        self.strip_metadata = strip_metadata
        self.id_re = re.compile(
            rf"(?<![A-Za-z0-9_\-+/])[A-Za-z0-9_\-+/]{{{min_id_length},}}={{0,2}}(?![A-Za-z0-9_\-+/])"
        )
        self.findings: list[tuple[str, str, str]] = []  # (kind, text, where)
        self.counts: Counter = Counter()
        self.warnings: list[str] = []

    # -- bookkeeping -------------------------------------------------------

    def record(self, kind: str, text: str, where: str) -> None:
        self.findings.append((kind, text, where))
        self.counts[kind] += 1

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    # -- detection ---------------------------------------------------------

    def find_spans(self, text: str, detectors: bool = True) -> list[Span]:
        """Return non-overlapping spans to replace, in text order.

        detectors=False limits matching to the supplied terms (for markup such
        as XMP, where IDs and URIs are structure, not content).
        """
        cands: list[tuple[int, int, int, str, str]] = []  # start, end, priority, kind, repl
        for rx in self.term_res:
            for m in rx.finditer(text):
                cands.append((m.start(), m.end(), 0, "term", self.replacement))
        if self.ip and detectors:
            cands += self._ip_candidates(text)
        if self.numbers and detectors:
            for m in NUMBER_RE.finditer(text):
                cands.append((m.start(), m.end(), 2, "number", KIND_TAGS["number"]))
        if self.ids and detectors:
            for m in self.id_re.finditer(text):
                for start, end in self._id_spans(m.group(), m.start()):
                    cands.append((start, end, 3, "id", KIND_TAGS["id"]))

        spans: list[Span] = []
        last_end = -1
        for start, end, _prio, kind, repl in sorted(cands, key=lambda c: (c[0], c[2], -c[1])):
            if start < last_end:
                continue
            if kind != "term" and self._is_kept(text[start:end]):
                continue
            spans.append(Span(start, end, kind, repl))
            last_end = end
        return spans

    def _is_kept(self, matched: str) -> bool:
        m = matched.lower()
        return any(fnmatch.fnmatchcase(m, pattern) for pattern in self.keep)

    def _ip_candidates(self, text: str) -> list[tuple[int, int, int, str, str]]:
        out = []
        for m in IPV4_RE.finditer(text):
            start, end = m.span()
            octets = m.group().split(".")
            if any(int(o) > 255 for o in octets):
                continue
            if any(len(o) > 1 and o[0] == "0" for o in octets):
                continue  # 01.02.03.04 is a version/date, not an address
            tail = text[end:end + 2]
            if re.match(r"\.\d", tail):
                continue  # 1.2.3.4.5 is a longer version string
            if re.match(r"[A-Za-z]|[-+_][A-Za-z]", tail):
                continue  # 1.2.3.4-beta, 1.2.3.4rc1
            if VERSION_PREFIX_RE.search(text[max(0, start - 16):start]):
                continue
            out.append((start, end, 1, "ip", KIND_TAGS["ip"]))
        for m in IPV6_RE.finditer(text):
            if len(m.group()) < 3:
                continue
            try:
                ipaddress.IPv6Address(m.group())
            except ValueError:
                continue
            out.append((m.start(), m.end(), 1, "ip", KIND_TAGS["ip"]))
        return out

    def _id_spans(self, token: str, offset: int) -> list[tuple[int, int]]:
        """Spans of machine-style IDs in a candidate token.

        A token containing "/" is either base64 (scrub it whole) or a URL/file
        path whose segments are words (scrub only the ID-like segments).
        """
        if "/" not in token or not self._is_path_like(token):
            return [(offset, offset + len(token))] if self._is_machine_id(token) else []
        return [
            (offset + seg.start(), offset + seg.end())
            for seg in re.finditer(r"[^/]+", token)
            if len(seg.group()) >= self.min_id_length and self._is_machine_id(seg.group())
        ]

    def _is_path_like(self, token: str) -> bool:
        return any(
            len(seg) >= 4 and self._word_coverage(seg) >= 0.8 for seg in token.split("/")
        )

    def _is_machine_id(self, token: str) -> bool:
        core = token.rstrip("=")
        alnum = re.sub(r"[^A-Za-z0-9]", "", core)
        if not alnum or len(alnum) < 0.75 * len(core):
            return False
        entropy = _entropy(alnum)
        classes = sum([
            any(c.islower() for c in alnum),
            any(c.isupper() for c in alnum),
            any(c.isdigit() for c in alnum),
        ])
        if entropy < 3.0 or (classes < 2 and entropy < 3.6):
            return False
        return self._word_coverage(core) < 0.4

    def _word_coverage(self, token: str) -> float:
        """Fraction of the token's alphanumerics that sit inside dictionary words."""
        words = _load_words(self)
        if not words:
            return 0.0
        covered = 0
        for run in re.findall(r"[A-Za-z]{4,}", token):
            run = run.lower()
            i = 0
            while i < len(run):
                for length in range(min(20, len(run) - i), 3, -1):
                    if run[i:i + length] in words:
                        covered += length
                        i += length
                        break
                else:
                    i += 1
        return covered / max(1, len(re.sub(r"[^A-Za-z0-9]", "", token)))

    # -- text helpers ------------------------------------------------------

    def scrub_text(self, text: str, where: str = "text", detectors: bool = True) -> tuple[str, int]:
        spans = self.find_spans(text, detectors)
        if not spans:
            return text, 0
        out, pos = [], 0
        for sp in spans:
            out.append(text[pos:sp.start])
            out.append(sp.repl)
            pos = sp.end
            self.record(sp.kind, text[sp.start:sp.end], where)
        out.append(text[pos:])
        return "".join(out), len(spans)

    def scrub_name(self, name: str) -> str:
        """Scrub a filename stem without recording findings."""
        out, pos = [], 0
        for sp in self.find_spans(name):
            out.append(name[pos:sp.start])
            out.append(sp.repl)
            pos = sp.end
        out.append(name[pos:])
        return "".join(out)


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())


@functools.cache
def _word_set() -> frozenset[str]:
    if not WORDS_PATH.exists():
        return frozenset()
    lines = WORDS_PATH.read_text(errors="ignore").splitlines()
    return frozenset(w for w in (l.strip().lower() for l in lines) if 4 <= len(w) <= 20 and w.isalpha())


def _load_words(sc: Scrubber) -> frozenset[str]:
    words = _word_set()
    if not words and not any("dictionary" in w for w in sc.warnings):
        sc.warn(f"word list {WORDS_PATH} not found; ID detection is not filtering readable identifiers")
    return words


# -- optional dependencies -------------------------------------------------

def _pymupdf():
    try:
        import pymupdf
    except ImportError:
        try:
            import fitz as pymupdf
        except ImportError:
            die("pymupdf is required for PDF support: pip install pymupdf")
    return pymupdf


@functools.cache
def _imaging():
    try:
        import pytesseract
        from PIL import Image, ImageDraw
    except ImportError:
        die("image support needs: pip install Pillow pytesseract")
    try:
        pytesseract.get_tesseract_version()
    except pytesseract.TesseractNotFoundError:
        die("image support needs the tesseract binary: brew install tesseract")
    return pytesseract, Image, ImageDraw


def _lxml():
    try:
        from lxml import etree
    except ImportError:
        die("Office file support needs: pip install lxml")
    return etree


# -- image redaction -------------------------------------------------------

def redact_image(img, sc: Scrubber, where: str):
    """OCR img, black out words that match, return (new_image, hit_count)."""
    pytesseract, Image, ImageDraw = _imaging()
    base = img if img.mode in ("RGB", "RGBA", "L") else img.convert("RGB")
    rgb = base.convert("RGB")
    width, height = rgb.size
    scale = 2 if max(width, height) < 2000 else 1
    ocr_img = rgb.resize((width * scale, height * scale), Image.LANCZOS) if scale > 1 else rgb

    boxes: set[tuple[int, int, int, int]] = set()
    hits: dict[tuple, tuple[str, str]] = {}
    # psm 3 reads page-like layouts, psm 11 finds scattered text in screenshots.
    for psm in (3, 11):
        data = pytesseract.image_to_data(
            ocr_img, config=f"--psm {psm}", output_type=pytesseract.Output.DICT
        )
        lines: dict[tuple, list] = {}
        for i, word in enumerate(data["text"]):
            if not word.strip() or float(data["conf"][i]) < 0:
                continue
            box = (
                data["left"][i],
                data["top"][i],
                data["left"][i] + data["width"][i],
                data["top"][i] + data["height"][i],
            )
            key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
            lines.setdefault(key, []).append((word, box))
        for words in lines.values():
            line_text, offsets = "", []
            for word, box in words:
                if line_text:
                    line_text += " "
                offsets.append((len(line_text), len(line_text) + len(word), box))
                line_text += word
            for sp in sc.find_spans(line_text):
                first = None
                for start, end, box in offsets:
                    if start < sp.end and end > sp.start:
                        boxes.add(box)
                        first = first or box
                if first:
                    hits[(sp.kind, line_text[sp.start:sp.end], first[0] // 30, first[1] // 30)] = (
                        sp.kind, line_text[sp.start:sp.end]
                    )

    for kind, text in hits.values():
        sc.record(kind, text, where)

    out = base.copy()
    if boxes and not sc.dry_run:
        fill = 0 if base.mode == "L" else ((0, 0, 0, 255) if base.mode == "RGBA" else (0, 0, 0))
        draw = ImageDraw.Draw(out)
        for left, top, right, bottom in boxes:
            # OCR boxes run tight; pad by a share of the text height so no glyph edge survives.
            pad = max(4, (bottom - top) / scale * 0.3)
            draw.rectangle(
                [left / scale - pad, top / scale - pad, right / scale + pad, bottom / scale + pad],
                fill=fill,
            )
    return out, len(hits)


def _scrub_image_bytes(data: bytes, sc: Scrubber, where: str) -> bytes | None:
    """Return redacted image bytes, or None if nothing needs to change."""
    _, Image, _ = _imaging()
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.load()
            if getattr(img, "n_frames", 1) > 1:
                sc.warn(f"{where}: animated/multi-frame image not scrubbed")
                return None
            fmt = img.format
            out, count = redact_image(img, sc, where)
    except Exception as exc:
        sc.warn(f"{where}: could not process image ({exc})")
        return None
    if not count and not sc.strip_metadata:
        return None
    buf = io.BytesIO()
    kwargs = {"quality": 95} if fmt == "JPEG" else {}
    out.save(buf, format=fmt, **kwargs)  # Pillow drops EXIF/text chunks unless passed back in
    return buf.getvalue()


# -- handlers --------------------------------------------------------------

class FileHandler(ABC):
    @abstractmethod
    def scrub(self, input_path: Path, output_path: Path, sc: Scrubber) -> int:
        """Write scrubbed content to output_path. Return total replacement count."""


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
    def scrub(self, input_path, output_path, sc):
        scrubbed, count = sc.scrub_text(input_path.read_text(), input_path.name)
        if not sc.dry_run:
            output_path.write_text(scrubbed)
        return count


class ImageHandler(FileHandler):
    def scrub(self, input_path, output_path, sc):
        _, Image, _ = _imaging()
        with Image.open(input_path) as img:
            img.load()
            if getattr(img, "n_frames", 1) > 1:
                sc.warn(f"{input_path.name}: multi-frame image, only the first frame was scrubbed")
            fmt = img.format
            extras = {}
            if not sc.strip_metadata:
                for key in ("exif", "icc_profile"):
                    if img.info.get(key):
                        extras[key] = img.info[key]
            out, count = redact_image(img, sc, input_path.name)
        if sc.dry_run:
            return count
        if not count and not sc.strip_metadata:
            shutil.copyfile(input_path, output_path)
            return 0
        if fmt == "JPEG":
            extras["quality"] = 95
        out.save(output_path, format=fmt, **extras)
        return count


class PdfHandler(FileHandler):
    def scrub(self, input_path, output_path, sc):
        pm = _pymupdf()
        doc = pm.open(str(input_path))
        if doc.needs_pass:
            die(f"{input_path.name} is password protected")
        count = 0
        count += self._metadata(doc, sc)

        if any(True for page in doc for _ in page.annots()) or any(
            True for page in doc for _ in page.widgets()
        ):
            sc.warn("PDF has annotations or form fields; their text is not scrubbed")
        if doc.embfile_count() and not sc.strip_metadata:
            sc.warn("PDF has embedded files; they are not scrubbed (use --strip-metadata to drop them)")

        seen: set[int] = set()
        for page in doc:
            for info in page.get_images(full=True):
                xref = info[0]
                if xref not in seen:
                    seen.add(xref)
                    count += self._image(doc, page, xref, sc)

        for page in doc:
            count += self._text(pm, page, sc)

        if not sc.dry_run:
            if sc.strip_metadata:
                try:
                    doc.scrub(
                        metadata=True, xml_metadata=True, attached_files=True,
                        embedded_files=True, javascript=True, thumbnails=True,
                        hidden_text=True, redactions=False, remove_links=False,
                        reset_fields=False, reset_responses=False,
                    )
                except TypeError:
                    doc.scrub()
            doc.save(str(output_path), garbage=3, deflate=True)
        return count

    def _metadata(self, doc, sc):
        count = 0
        if sc.strip_metadata:
            if not sc.dry_run:
                doc.set_metadata({})
                doc.del_xml_metadata()
            return 0
        meta = dict(doc.metadata or {})
        writable = ("author", "title", "subject", "keywords", "creator", "producer")
        changed = {}
        for key in writable:
            if meta.get(key):
                new, n = sc.scrub_text(meta[key], f"metadata:{key}")
                if n:
                    changed[key] = new
                    count += n
        xmp = doc.get_xml_metadata()
        if xmp:
            new_xmp, n = sc.scrub_text(xmp, "metadata:xmp", detectors=False)
            if n and not sc.dry_run:
                doc.set_xml_metadata(new_xmp)
            count += n
        if changed and not sc.dry_run:
            doc.set_metadata({**{k: meta.get(k) or "" for k in writable}, **changed})
        toc = doc.get_toc()
        new_toc, toc_changed = [], False
        for level, title, page_no in toc:
            new_title, n = sc.scrub_text(title, "bookmark")
            toc_changed |= bool(n)
            count += n
            new_toc.append([level, new_title, page_no])
        if toc_changed and not sc.dry_run:
            doc.set_toc(new_toc)
        return count

    def _image(self, doc, page, xref, sc):
        _, Image, _ = _imaging()
        where = f"page {page.number + 1} image"
        try:
            info = doc.extract_image(xref)
            with Image.open(io.BytesIO(info["image"])) as img:
                img.load()
                if min(img.size) < 24:
                    return 0
                out, count = redact_image(img, sc, where)
        except Exception as exc:
            sc.warn(f"{where} (xref {xref}): could not decode image ({exc})")
            return 0
        if count and not sc.dry_run:
            buf = io.BytesIO()
            if info["ext"] in ("jpg", "jpeg"):
                out.convert("RGB").save(buf, format="JPEG", quality=92)
            else:
                out.save(buf, format="PNG")
            page.replace_image(xref, stream=buf.getvalue())
        return count

    def _text(self, pm, page, sc):
        where = f"page {page.number + 1}"
        targets: dict[str, tuple[str, str]] = {t: ("term", sc.replacement) for t in sc.terms}
        text = page.get_text("text")
        for sp in sc.find_spans(text):
            if sp.kind != "term":
                targets.setdefault(text[sp.start:sp.end], (sp.kind, sp.repl))

        count = 0
        for needle, (kind, repl) in targets.items():
            try:
                rects = page.search_for(needle, hit_max=1000)
            except TypeError:
                rects = page.search_for(needle)
            if not rects and kind != "term":
                sc.warn(f"{where}: could not locate {kind} to redact: {needle!r}")
            for rect in rects:
                if not sc.dry_run:
                    page.add_redact_annot(rect, text=repl)
                sc.record(kind, needle, where)
                count += 1
        if count and not sc.dry_run:
            kwargs = {"images": pm.PDF_REDACT_IMAGE_NONE}
            if hasattr(pm, "PDF_REDACT_LINE_ART_NONE"):
                kwargs["graphics"] = pm.PDF_REDACT_LINE_ART_NONE
            try:
                page.apply_redactions(**kwargs)
            except TypeError:
                page.apply_redactions()
        return count


WML = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
DML = "http://schemas.openxmlformats.org/drawingml/2006/main"
SML = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
PML = "http://schemas.openxmlformats.org/presentationml/2006/main"
TCM = "http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"

# Text runs are grouped by their paragraph so a term split across runs still matches.
RUN_TEXT_TAGS = {f"{{{WML}}}t", f"{{{WML}}}delText", f"{{{DML}}}t", f"{{{SML}}}t"}
PARAGRAPH_TAGS = {f"{{{WML}}}p", f"{{{DML}}}p", f"{{{SML}}}si", f"{{{SML}}}is", f"{{{SML}}}text"}
LEAF_TEXT_TAGS = {f"{{{WML}}}instrText", f"{{{PML}}}text", f"{{{TCM}}}text", f"{{{SML}}}author"}
SCRUBBED_ATTRS = {"descr", "title", "instr", "author", "initials", "displayName", "userId"}
STRIPPED_ATTR_VALUES = {
    "author": "Author", "initials": "A", "displayName": "Author", "userId": "user",
}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff"}
UNHANDLED_IMAGE_EXTS = {".emf", ".wmf", ".svg", ".wdp", ".jxr"}
MAX_UNZIPPED_BYTES = 2 * 1024 ** 3


class OfficeHandler(FileHandler):
    """.docx / .pptx / .xlsx: scrub text, alt text, metadata and embedded images."""

    def scrub(self, input_path, output_path, sc):
        etree = _lxml()
        try:
            zin = zipfile.ZipFile(input_path)
        except zipfile.BadZipFile:
            die(f"{input_path.name} is not a valid Office Open XML file (encrypted or legacy format?)")
        count = 0
        entries: list[tuple[zipfile.ZipInfo, bytes]] = []
        with zin:
            if sum(i.file_size for i in zin.infolist()) > MAX_UNZIPPED_BYTES:
                die(f"{input_path.name} expands to more than 2 GiB; refusing to process it")
            for info in zin.infolist():
                data = zin.read(info)
                name = info.filename
                lower = name.lower()
                suffix = Path(lower).suffix
                if info.is_dir():
                    pass
                elif lower.endswith((".xml", ".rels")):
                    data, n = self._xml_part(etree, data, name, sc)
                    count += n
                elif suffix in IMAGE_EXTS and ("/media/" in lower or lower.startswith("docprops/thumbnail")):
                    new = _scrub_image_bytes(data, sc, name)
                    if new is not None:
                        data = new
                elif suffix in UNHANDLED_IMAGE_EXTS:
                    sc.warn(f"{name}: {suffix} image not scrubbed (cannot OCR it)")
                elif "/printersettings/" in lower:
                    pass  # opaque printer config Office adds to most files; see README
                elif "/embeddings/" in lower or suffix == ".bin":
                    sc.warn(f"{name}: embedded object not scrubbed")
                entries.append((info, data))
            self._residual_check(entries, sc)

        if not sc.dry_run:
            with zipfile.ZipFile(output_path, "w") as zout:
                for info, data in entries:
                    zi = zipfile.ZipInfo(
                        info.filename,
                        date_time=(1980, 1, 1, 0, 0, 0) if sc.strip_metadata else info.date_time,
                    )
                    zi.compress_type = info.compress_type
                    zi.external_attr = info.external_attr
                    zout.writestr(zi, data)
        return count

    def _xml_part(self, etree, data, name, sc):
        parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True)
        try:
            root = etree.fromstring(data, parser)
        except etree.XMLSyntaxError:
            sc.warn(f"{name}: could not parse XML; left unchanged")
            return data, 0
        lower = name.lower()
        count = 0
        if lower.endswith(".rels"):
            for rel in root.iter():
                if isinstance(rel.tag, str) and rel.get("TargetMode") == "External":
                    new, n = sc.scrub_text(rel.get("Target", ""), name)
                    if n:
                        rel.set("Target", new)
                        count += n
        elif lower.startswith(("docprops/", "customxml/")):
            count += self._properties(etree, root, lower, name, sc)
        else:
            count += self._body(etree, root, name, sc)
        count += self._attributes(etree, root, name, sc)
        if not count and not (sc.strip_metadata and lower.startswith("docprops/")):
            return data, 0
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True), count

    def _body(self, etree, root, name, sc):
        count = 0
        groups: dict = {}
        for el in root.iter():
            if not isinstance(el.tag, str):
                continue
            if el.tag in RUN_TEXT_TAGS:
                owner = next((a for a in el.iterancestors() if a.tag in PARAGRAPH_TAGS), el)
                groups.setdefault(owner, []).append(el)
            elif el.tag in LEAF_TEXT_TAGS and el.text:
                if sc.strip_metadata and el.tag == f"{{{SML}}}author":
                    el.text = "Author"
                    continue
                el.text, n = sc.scrub_text(el.text, name)
                count += n
        for runs in groups.values():
            texts = [r.text or "" for r in runs]
            full = "".join(texts)
            spans = sc.find_spans(full)
            if not spans:
                continue
            chars = list(full)
            for sp in spans:
                chars[sp.start] = sp.repl
                for k in range(sp.start + 1, sp.end):
                    chars[k] = ""
                sc.record(sp.kind, full[sp.start:sp.end], name)
            pos = 0
            for run, text in zip(runs, texts):
                run.text = "".join(chars[pos:pos + len(text)])
                pos += len(text)
                if run.text != run.text.strip():
                    run.set(XML_SPACE, "preserve")
            count += len(spans)
        return count

    def _properties(self, etree, root, lower, name, sc):
        count = 0
        base = Path(lower).name
        for el in root.iter():
            if not isinstance(el.tag, str) or len(el) or not (el.text or "").strip():
                continue
            local = etree.QName(el).localname
            if sc.strip_metadata and lower.startswith("docprops/"):
                if base == "core.xml":
                    el.text = "1970-01-01T00:00:00Z" if local in ("created", "modified", "lastPrinted") else (
                        el.text if local == "revision" else ""
                    )
                elif base == "app.xml":
                    in_titles = any(etree.QName(a).localname == "TitlesOfParts" for a in el.iterancestors())
                    if local in ("Company", "Manager", "HyperlinkBase", "Template") or in_titles:
                        el.text = ""
                elif base == "custom.xml":
                    el.text = ""
            else:
                el.text, n = sc.scrub_text(el.text, name)
                count += n
        return count

    def _attributes(self, etree, root, name, sc):
        count = 0
        for el in root.iter():
            if not isinstance(el.tag, str):
                continue
            for key, value in list(el.attrib.items()):
                local = etree.QName(key).localname
                # Picture/shape names are labels (often the image filename); other
                # "name" attributes (sheet names, styles) are referenced elsewhere.
                is_label = local == "name" and etree.QName(el).localname in ("cNvPr", "docPr")
                if local not in SCRUBBED_ATTRS and not is_label:
                    continue
                if sc.strip_metadata and local in STRIPPED_ATTR_VALUES:
                    el.set(key, STRIPPED_ATTR_VALUES[local])
                    continue
                new, n = sc.scrub_text(value, name)
                if n:
                    el.set(key, new)
                    count += n
        return count

    def _residual_check(self, entries, sc):
        """Warn about supplied terms that survive in parts we do not rewrite."""
        for info, data in entries:
            if info.is_dir():
                continue
            haystacks = [(info.filename, info.filename)]
            if info.filename.lower().endswith((".xml", ".rels")):
                haystacks.append((info.filename, data.decode("utf-8", errors="ignore")))
            for part, text in haystacks:
                for term, rx in zip(sc.terms, sc.term_res):
                    if rx.search(text):
                        sc.warn(f"{part}: term {term!r} is still present (not in scrubbed text)")


# Register handlers here to add support for new formats.
HANDLERS: dict[str, FileHandler] = {
    ".txt": TxtHandler(),
    ".pdf": PdfHandler(),
    ".docx": OfficeHandler(),
    ".pptx": OfficeHandler(),
    ".xlsx": OfficeHandler(),
    ".png": ImageHandler(),
    ".jpg": ImageHandler(),
    ".jpeg": ImageHandler(),
    ".bmp": ImageHandler(),
    ".webp": ImageHandler(),
}


def main():
    supported = ", ".join(HANDLERS)
    parser = argparse.ArgumentParser(
        description=f"Replace sensitive strings and patterns in file content and filename. "
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
        help="Replacement string for --scrub/--terms matches (default: dummy)",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory to write the scrubbed file (default: same as input)",
    )
    parser.add_argument("--no-ip", action="store_true", help="Do not auto-detect IP addresses")
    parser.add_argument("--no-numbers", action="store_true", help="Do not auto-detect numbers of 13+ digits")
    parser.add_argument("--no-ids", action="store_true", help="Do not auto-detect long machine-style IDs")
    parser.add_argument(
        "--min-id-length",
        type=int,
        default=24,
        metavar="N",
        help="Minimum length of a machine-style ID (default: 24)",
    )
    parser.add_argument(
        "--keep",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Never auto-scrub detected matches that fit this pattern, e.g. --keep '10.2.*' "
             "(case-insensitive, * and ? wildcards, repeatable). Does not apply to --scrub terms.",
    )
    parser.add_argument(
        "--strip-metadata",
        action="store_true",
        help="Also remove document properties, authors, EXIF and embedded files",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List what would be scrubbed without writing anything",
    )
    args = parser.parse_args()

    terms = list(args.terms)
    if args.terms_file:
        terms_path = Path(args.terms_file)
        if not terms_path.exists():
            die(f"terms file not found: {terms_path}")
        terms.extend(_load_terms_file(terms_path))

    detectors = not (args.no_ip and args.no_numbers and args.no_ids)
    if not terms and not detectors:
        die("provide at least one --scrub STRING or --terms FILE, or enable a detector")

    input_path = Path(args.input_file)
    if not input_path.exists():
        die(f"file not found: {input_path}")

    ext = input_path.suffix.lower()
    handler = HANDLERS.get(ext)
    if handler is None:
        die(f"unsupported format '{ext}'. Supported: {supported}")

    sc = Scrubber(
        terms,
        args.replacement,
        ip=not args.no_ip,
        numbers=not args.no_numbers,
        ids=not args.no_ids,
        min_id_length=args.min_id_length,
        keep=args.keep,
        dry_run=args.dry_run,
        strip_metadata=args.strip_metadata,
    )

    scrubbed_stem = sc.scrub_name(input_path.stem) or "scrubbed"
    scrubbed_name = scrubbed_stem + input_path.suffix
    output_dir = Path(args.output_dir) if args.output_dir else input_path.parent
    output_path = output_dir / scrubbed_name

    if output_path.resolve() == input_path.resolve():
        die("output path is the same as input — use --output-dir to specify a different location.")

    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = _unique_output_path(output_path)

    handler.scrub(input_path, output_path, sc)

    total = sum(sc.counts.values())
    if args.dry_run:
        print("Dry run: nothing written.")
        print(f"Would write:          {output_path}")
        for kind, text, where in sc.findings:
            print(f"  {kind:<7} {text!r}  ({where})")
    else:
        print(f"Wrote:                {output_path}")
    print(f"Terms scrubbed:       {len(sc.terms)}")
    print(
        f"Content replacements: {total} "
        f"(terms {sc.counts['term']}, IPs {sc.counts['ip']}, "
        f"numbers {sc.counts['number']}, IDs {sc.counts['id']})"
    )
    print(f"Filename changed:     {scrubbed_name != input_path.name}")

    if sc.warnings:
        print("\nWARNINGS — review before sharing:", file=sys.stderr)
        for warning in dict.fromkeys(sc.warnings):
            print(f"  - {warning}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
