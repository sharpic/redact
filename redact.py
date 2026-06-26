#!/usr/bin/env python3
"""
redact.py — Redact PII in documents.

Replaces personally identifiable information (PII) in a document with
consistent placeholders, and writes a JSON mapping file that can later
be used to restore the originals.

Supported input formats
-----------------------
  .docx   Microsoft Word
  .odt    LibreOffice / OpenDocument Text
  .xlsx   Microsoft Excel
  .pdf    PDF (output is plain text — formatting cannot be preserved)

Detected PII (default config)
------------------------------
  email      user@domain.tld                → person001@anon.invalid
  name       Alice Smith                    → Person001
  id         1234567  /  12345678           → same-width zero-padded number
  username   ab12cd34  (8-char alphanumeric)→ user0001xx

All patterns are defined in redact_config.toml.
Add a [[patterns]] block there to extend detection — no Python changes needed.

Output files
------------
  <stem>_redacted.<ext>   redacted copy of the document
  <stem>_mapping.json     pseudonym → original  (keep this safe; it reverses the process)

Install dependencies
--------------------
  pip install python-docx odfpy openpyxl pdfplumber
  pip install spacy && python -m spacy download en_core_web_sm  # recommended for names
"""

import re
import json
import sys
import tomllib
import argparse
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime


# ── Config loading ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG = Path(__file__).with_name('redact_config.toml')


def load_config(path: Path) -> dict:
    """Load and return the TOML config dict, exiting with an error if not found."""
    if not path.exists():
        sys.exit(
            f'Error: config file not found: {path}\n'
            f'       Expected redact_config.toml next to the script,\n'
            f'       or specify one with --config <file>.'
        )
    with open(path, 'rb') as f:
        return tomllib.load(f)


@dataclass
class PatternDef:
    name: str
    template: str
    regex: re.Pattern | None = None
    spacy_ner: bool = False
    spacy_labels: list = field(default_factory=lambda: ['PERSON'])
    exclusions: frozenset = frozenset()
    min_word_length: int = 1


def build_patterns(config: dict) -> list[PatternDef]:
    """Compile each [[patterns]] entry from the config into a PatternDef.

    Regex strings are compiled here so misconfigured patterns fail at startup,
    not mid-document.  Optional regex_flags are OR-ed in from the re module.
    """
    patterns = []
    for p in config.get('patterns', []):
        flags = 0
        for flag_name in p.get('regex_flags', []):
            flags |= getattr(re, flag_name)

        compiled = re.compile(p['regex'], flags) if 'regex' in p else None

        patterns.append(PatternDef(
            name=p['name'],
            template=p['template'],
            regex=compiled,
            spacy_ner=p.get('spacy_ner', False),
            spacy_labels=p.get('spacy_labels', ['PERSON']),
            exclusions=frozenset(p.get('exclusions', [])),
            min_word_length=p.get('min_word_length', 1),
        ))
    return patterns


# ── PseudonymRegistry ──────────────────────────────────────────────────────────

def _apply_template(template: str, n: int, original: str) -> str:
    """Render a pseudonym from a template string and a sequential counter.

    Supports {n} (counter), {orig} (original text), {orig_len} (its length),
    and the special keyword 'preserve_length' which zero-pads n to match the
    digit count of the original value.
    """
    if template == 'preserve_length':
        return str(n).zfill(len(original))
    return template.format(n=n, orig=original, orig_len=len(original))


class PseudonymRegistry:
    """Consistent original→pseudonym mapping; never re-uses a pseudonym."""

    def __init__(self):
        self._map = {}       # (pattern_name, original_stripped) → pseudonym
        self._counters = {}

    def get_or_create(self, original: str, pat: PatternDef) -> str:
        key = (pat.name, original.strip())
        if key not in self._map:
            n = self._counters.get(pat.name, 0) + 1
            self._counters[pat.name] = n
            self._map[key] = _apply_template(pat.template, n, original)
        return self._map[key]

    def mapping_file_dict(self) -> dict:
        """Return {pseudonym: original} — the restoration key."""
        return {v: k[1] for k, v in self._map.items()}

    def stats(self) -> dict:
        return dict(self._counters)


# ── Core text redaction ────────────────────────────────────────────────────────

def _overlaps(spans: list, start: int, end: int) -> bool:
    """Return True if (start, end) overlaps any span already in the list."""
    return any(s < end and e > start for s, e, _ in spans)


def _passes_exclusions(text: str, pat: PatternDef) -> bool:
    """Return True if none of the words in text are in the pattern's exclusion set
    and every word meets the minimum length requirement."""
    words = text.split()
    if pat.min_word_length > 1 and any(len(w) < pat.min_word_length for w in words):
        return False
    return not any(w in pat.exclusions for w in words)


def redact_text(text: str, registry: PseudonymRegistry,
                patterns: list[PatternDef], nlp=None) -> str:
    """Scan text for PII using each pattern in order and replace with pseudonyms.

    Patterns are applied in config order; the first pattern to claim a span
    prevents later patterns from overlapping it (so email beats name for
    'John.Smith@example.com').  spaCy NER is used when nlp is provided and
    the pattern has spacy_ner=true; otherwise the regex fallback is used.
    Exclusions are applied to both NER and regex matches.
    """
    if not text or not text.strip():
        return text

    spans = []  # (start, end, replacement_string)

    def _add(start, end, original, pat):
        if not _overlaps(spans, start, end):
            spans.append((start, end, registry.get_or_create(original, pat)))

    for pat in patterns:
        if pat.spacy_ner and nlp is not None:
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ in pat.spacy_labels and _passes_exclusions(ent.text, pat):
                    _add(ent.start_char, ent.end_char, ent.text, pat)
        elif pat.regex is not None:
            for m in pat.regex.finditer(text):
                if _passes_exclusions(m.group(), pat):
                    _add(m.start(), m.end(), m.group(), pat)

    if not spans:
        return text

    # Apply in reverse order so earlier offsets stay valid
    spans.sort(key=lambda x: x[0], reverse=True)
    chars = list(text)
    for start, end, repl in spans:
        chars[start:end] = list(repl)
    return ''.join(chars)


# ── Core text restoration ──────────────────────────────────────────────────────

def restore_text(text: str, pseudo_to_orig: dict) -> str:
    """Replace every pseudonym in text with its original value.

    Replacements are applied longest-first so that 'person001@anon.invalid'
    is replaced before 'person001', preventing partial corruption.
    """
    if not text:
        return text
    for pseudo, orig in sorted(pseudo_to_orig.items(), key=lambda x: -len(x[0])):
        text = text.replace(pseudo, orig)
    return text


# ── File handlers ──────────────────────────────────────────────────────────────

def _process_docx_para(para, transform_fn):
    """Redact one paragraph by concatenating all runs, transforming, then
    writing the result into the first run and clearing the rest.

    Note: this preserves paragraph-level formatting (style, alignment) but
    collapses per-run character formatting (bold/italic on individual words)
    within any replaced span.
    """
    if not para.runs:
        return
    full = ''.join(r.text for r in para.runs)
    transformed = transform_fn(full)
    if transformed != full:
        para.runs[0].text = transformed
        for r in para.runs[1:]:
            r.text = ''


def process_docx(input_path: Path, output_path: Path, transform_fn):
    """Apply transform_fn to every text span in a .docx file and save the result."""
    from docx import Document
    doc = Document(str(input_path))

    def walk(container):
        for para in container.paragraphs:
            _process_docx_para(para, transform_fn)
        for table in container.tables:
            for row in table.rows:
                for cell in row.cells:
                    walk(cell)

    walk(doc)
    for section in doc.sections:
        for hf in (section.header, section.footer):
            if hf:
                walk(hf)

    doc.save(str(output_path))


def process_odt(input_path: Path, output_path: Path, transform_fn):
    """Apply transform_fn to every text node in a .odt file and save the result."""
    from odf.opendocument import load as odf_load

    doc = odf_load(str(input_path))

    def walk(element):
        for child in list(element.childNodes):
            if hasattr(child, 'data'):
                transformed = transform_fn(child.data)
                if transformed != child.data:
                    child.data = transformed
            else:
                walk(child)

    walk(doc.text)
    doc.save(str(output_path))


def process_xlsx(input_path: Path, output_path: Path, transform_fn):
    """Apply transform_fn to every string cell across all sheets and save the result.
    Numeric and formula cells are left untouched.
    """
    import openpyxl
    wb = openpyxl.load_workbook(str(input_path))

    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, str):
                    transformed = transform_fn(cell.value)
                    if transformed != cell.value:
                        cell.value = transformed

    wb.save(str(output_path))


def process_pdf(input_path: Path, output_path: Path, transform_fn):
    """Extract text from each PDF page, apply transform_fn line-by-line, and
    write the result as plain text.  PDF formatting is not preserved.
    """
    import pdfplumber

    pages = []
    with pdfplumber.open(str(input_path)) as pdf:
        for i, page in enumerate(pdf.pages, 1):
            raw = page.extract_text() or ''
            lines = [transform_fn(line) for line in raw.splitlines()]
            pages.append(f'--- Page {i} ---\n' + '\n'.join(lines))

    output_path.write_text('\n\n'.join(pages), encoding='utf-8')
    print(f'[note] PDF output is plain text (formatting cannot be preserved): {output_path}')


_HANDLERS = {
    '.docx': (process_docx, '.docx', 'python-docx'),
    '.odt':  (process_odt,  '.odt',  'odfpy'),
    '.xlsx': (process_xlsx, '.xlsx', 'openpyxl'),
    '.pdf':  (process_pdf,  '.txt',  'pdfplumber'),
}

_RESTORE_SUFFIX = {'.docx': '.docx', '.odt': '.odt', '.xlsx': '.xlsx', '.txt': '.txt'}


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_redact(args):
    input_path = Path(args.input)
    if not input_path.exists():
        sys.exit(f'Error: not found: {input_path}')

    suffix = input_path.suffix.lower()
    if suffix not in _HANDLERS:
        sys.exit(f"Error: unsupported type '{suffix}'. Supported: {', '.join(_HANDLERS)}")

    handler, out_suffix, lib = _HANDLERS[suffix]
    output_path = (Path(args.output) if args.output
                   else input_path.with_name(input_path.stem + '_redacted' + out_suffix))
    mapping_path = (Path(args.mapping) if args.mapping
                    else input_path.with_name(input_path.stem + '_mapping.json'))

    config = load_config(Path(args.config))
    patterns = build_patterns(config)
    if not patterns:
        sys.exit('Error: no [[patterns]] defined in config file.')

    # Load spaCy if any pattern requests it
    nlp = None
    needs_ner = any(p.spacy_ner for p in patterns)
    if needs_ner and not args.no_spacy:
        model = config.get('settings', {}).get('spacy_model', 'en_core_web_sm')
        try:
            import spacy
            nlp = spacy.load(model)
            print(f'[info] spaCy NER active ({model}).')
        except ImportError:
            print('[info] spaCy not installed — using regex heuristic for names.')
            print('       pip install spacy && python -m spacy download', model)
        except OSError:
            print(f'[info] spaCy model "{model}" not found — using regex heuristic.')
            print('       python -m spacy download', model)

    registry = PseudonymRegistry()
    transform = lambda text: redact_text(text, registry, patterns, nlp)

    print(f'Redacting:   {input_path}')
    try:
        handler(input_path, output_path, transform)
    except ImportError as exc:
        sys.exit(f'Missing library — run: pip install {lib}\n  ({exc})')

    mapping_doc = {
        'source_file': str(input_path.resolve()),
        'redacted_file': str(output_path.resolve()),
        'created': datetime.now().isoformat(timespec='seconds'),
        'spacy_ner_used': nlp is not None,
        'stats': registry.stats(),
        'mapping': registry.mapping_file_dict(),
    }
    mapping_path.write_text(
        json.dumps(mapping_doc, indent=2, ensure_ascii=False), encoding='utf-8'
    )

    stats = registry.stats()
    total = sum(stats.values())
    print(f'Output:      {output_path}')
    print(f'Mapping:     {mapping_path}')
    if total:
        print(f'Replaced:    {total} items — ' +
              ', '.join(f'{v} {k}(s)' for k, v in stats.items()))
    else:
        print('[note] No PII detected.')
        if not nlp:
            print('       Install spaCy for better name detection.')


def cmd_restore(args):
    input_path = Path(args.input)
    if not input_path.exists():
        sys.exit(f'Error: not found: {input_path}')

    mapping_path = Path(args.mapping) if args.mapping else None
    if mapping_path is None:
        stem = input_path.stem
        if stem.endswith('_redacted'):
            stem = stem[:-9]
        mapping_path = input_path.with_name(stem + '_mapping.json')

    if not mapping_path.exists():
        sys.exit(f'Error: mapping file not found: {mapping_path}\n'
                 f'       Specify it with --mapping <file>')

    mapping_doc = json.loads(mapping_path.read_text(encoding='utf-8'))
    pseudo_to_orig = mapping_doc.get('mapping', {})
    if not pseudo_to_orig:
        sys.exit('Error: mapping file contains no entries.')

    suffix = input_path.suffix.lower()
    if suffix not in _HANDLERS and suffix != '.txt':
        sys.exit(f"Error: unsupported type '{suffix}'.")

    out_suffix = _RESTORE_SUFFIX.get(suffix, suffix)
    output_path = (Path(args.output) if args.output
                   else input_path.with_name(input_path.stem + '_restored' + out_suffix))

    transform = lambda text: restore_text(text, pseudo_to_orig)

    print(f'Restoring:   {input_path}')
    try:
        if suffix == '.txt':
            output_path.write_text(
                transform(input_path.read_text(encoding='utf-8')), encoding='utf-8'
            )
        else:
            handler, _, lib = _HANDLERS[suffix]
            handler(input_path, output_path, transform)
    except ImportError as exc:
        _, _, lib = _HANDLERS.get(suffix, (None, None, 'unknown'))
        sys.exit(f'Missing library — run: pip install {lib}\n  ({exc})')

    print(f'Restored:    {output_path}')
    print(f'Applied {len(pseudo_to_orig)} mapping(s) from {mapping_path}')


# ── Entry point ────────────────────────────────────────────────────────────────

_EXAMPLES = """
examples:
  # Redact a Word document (output: report_redacted.docx + report_mapping.json)
  python3 redact.py report.docx

  # Redact an Excel spreadsheet with custom output paths
  python3 redact.py data.xlsx -o data_safe.xlsx -m data_keys.json

  # Redact a PDF (output is plain text — PDF formatting cannot be preserved)
  python3 redact.py notes.pdf

  # Restore — auto-locates the mapping file from the filename
  python3 redact.py report_redacted.docx --restore
  # → report_redacted_restored.docx

  # Restore with an explicit mapping file
  python3 redact.py report_redacted.docx -r -m /secure/report_mapping.json

  # Use a custom pattern config instead of the default
  python3 redact.py report.docx --config my_patterns.toml

  # Disable spaCy NER (faster, uses regex heuristic for names instead)
  python3 redact.py report.docx --no-spacy

detected PII  (default config — edit redact_config.toml to extend):
  email      user@domain.tld              → person001@anon.invalid
  name       Alice Smith                  → Person001  (spaCy NER or title-case heuristic)
  id         1234567  /  12345678         → 0000001  /  00000001  (same digit count)
  username   ab12cd34  (8-char mixed)     → user0001xx

output files:
  <stem>_redacted.<ext>   redacted copy of the document
  <stem>_mapping.json     pseudonym→original map — keep this safe and separate
                          from the redacted file; it is the only way to reverse
                          the process

adding new patterns:
  Append a [[patterns]] block to redact_config.toml.  No Python
  changes are needed.  Example — UK National Insurance numbers:

    [[patterns]]
    name    = "ni_number"
    regex   = '\\b[A-CEGHJ-PR-TW-Z]{2}\\d{6}[A-D]\\b'
    regex_flags = ["IGNORECASE"]
    template = "NI{n:04d}"
"""


def main():
    parser = argparse.ArgumentParser(
        description=(
            'Redact PII in Word (.docx), ODT, Excel (.xlsx), and PDF files.\n'
            'Patterns are configured in redact_config.toml — add a [[patterns]]\n'
            'block there to extend detection without changing any Python code.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EXAMPLES,
    )
    parser.add_argument('input', help='Input file (.docx / .odt / .xlsx / .pdf)')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Output path (default: <input>_redacted.<ext>)')
    parser.add_argument('--mapping', '-m', metavar='FILE',
                        help='Mapping JSON path (default: <input>_mapping.json)')
    parser.add_argument('--config', '-c', metavar='FILE',
                        default=str(DEFAULT_CONFIG),
                        help=f'Config TOML path (default: {DEFAULT_CONFIG.name} next to script)')
    parser.add_argument('--no-spacy', action='store_true',
                        help='Disable spaCy NER (faster; uses regex heuristic for names)')
    parser.add_argument('--restore', '-r', action='store_true',
                        help='Reverse: restore originals from mapping file')

    args = parser.parse_args()

    if args.restore:
        cmd_restore(args)
    else:
        cmd_redact(args)


if __name__ == '__main__':
    main()
