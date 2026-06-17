# pseudo-anonymize

A local command-line tool that pseudo-anonymizes personally identifiable information (PII) in common document formats. It replaces names, email addresses, ID codes, and usernames with consistent placeholders, and writes a separate mapping file that can restore the originals at any time.

All detection patterns live in a plain TOML config file — adding a new pattern requires no Python knowledge.

---

## What it does

Given an input document, the tool produces two files:

| File | Purpose |
|---|---|
| `report_anon.docx` | Anonymized copy — safe to share |
| `report_mapping.json` | Pseudonym → original map — keep this secure |

The mapping file is the only way to reverse the process. Store it separately from the anonymized document.

---

## Detected PII (default config)

| Type | Example input | Replaced with |
|---|---|---|
| Email address | `alice@university.ac.uk` | `person001@anon.invalid` |
| Person name | `Alice Johnson` | `Person001` |
| 7- or 8-digit ID | `1234567` / `12345678` | `0000001` / `00000001` (same width) |
| 8-char alphanumeric code / username | `ab12cd34` | `user0001xx` |

- The same original value always gets the same pseudonym within a file (consistent replacement).
- Names use spaCy NER when available, falling back to a title-case word heuristic.
- All patterns are defined in [`pseudo_anonymize_config.toml`](pseudo_anonymize_config.toml) and can be extended without touching the Python code.

---

## Supported formats

| Format | Extension | Anonymized output |
|---|---|---|
| Microsoft Word | `.docx` | `.docx` |
| OpenDocument Text | `.odt` | `.odt` |
| Microsoft Excel | `.xlsx` | `.xlsx` |
| PDF | `.pdf` | `.txt` (plain text; PDF formatting cannot be preserved) |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/pseudo-anonymize.git
cd pseudo-anonymize
```

### 2. Install Python dependencies

```bash
pip install python-docx odfpy openpyxl pdfplumber
```

### 3. Install spaCy for better name detection (recommended)

```bash
pip install spacy
python -m spacy download en_core_web_sm
```

Without spaCy the tool falls back to a title-case word heuristic for names, which is less accurate but requires no additional dependencies.

> **Python version:** 3.11 or later required (uses the built-in `tomllib` parser).

---

## Usage

### Anonymize a document

```bash
python3 pseudo_anonymize.py <input_file>
```

Output files are created alongside the input:

```
report.docx          ← original (unchanged)
report_anon.docx     ← anonymized copy
report_mapping.json  ← reversal key
```

### Anonymize with custom output paths

```bash
python3 pseudo_anonymize.py data.xlsx -o data_safe.xlsx -m data_keys.json
```

### Anonymize a PDF

```bash
python3 pseudo_anonymize.py notes.pdf
# → notes_anon.txt  (plain text — PDF formatting is not preserved)
```

### De-anonymize (restore originals)

The tool auto-locates the mapping file from the filename:

```bash
python3 pseudo_anonymize.py report_anon.docx --deanonymize
# → report_anon_restored.docx
```

Or point to the mapping file explicitly:

```bash
python3 pseudo_anonymize.py report_anon.docx -d -m /secure/report_mapping.json
```

### Use a custom config file

```bash
python3 pseudo_anonymize.py report.docx --config my_patterns.toml
```

### Disable spaCy (faster, regex-only name detection)

```bash
python3 pseudo_anonymize.py report.docx --no-spacy
```

### Full option reference

```
positional arguments:
  input               Input file (.docx / .odt / .xlsx / .pdf)

options:
  -o, --output FILE   Output path  (default: <input>_anon.<ext>)
  -m, --mapping FILE  Mapping JSON (default: <input>_mapping.json)
  -c, --config FILE   Config TOML  (default: pseudo_anonymize_config.toml)
  --no-spacy          Use regex heuristic instead of spaCy for names
  -d, --deanonymize   Reverse mode: restore originals using mapping file
```

---

## Adding new patterns

Open `pseudo_anonymize_config.toml` and append a `[[patterns]]` block. No Python changes are needed.

### Example: UK National Insurance numbers

```toml
[[patterns]]
name        = "ni_number"
regex       = '\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b'
regex_flags = ["IGNORECASE"]
template    = "NI{n:04d}"
```

### Example: UK phone numbers

```toml
[[patterns]]
name     = "phone_uk"
regex    = '\b(?:0|\+44)\s*\d[\d\s]{8,12}\d\b'
template = "PHONE{n:03d}"
```

### Example: UK postcodes

```toml
[[patterns]]
name        = "postcode"
regex       = '\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b'
regex_flags = ["IGNORECASE"]
template    = "PC{n:03d}"
```

### Pattern fields reference

| Field | Type | Description |
|---|---|---|
| `name` | string | Identifier shown in stats and the mapping file |
| `regex` | string | Python regex — **use single quotes** to keep `\b` etc. literal |
| `spacy_ner` | bool | Use spaCy NER instead of (or in addition to) the regex |
| `spacy_labels` | list | NER entity labels to match (default: `["PERSON"]`) |
| `template` | string | Pseudonym format — see below |
| `exclusions` | list | Words that disqualify a match (case-sensitive) |
| `min_word_length` | int | Minimum character length per word in a multi-word match |
| `regex_flags` | list | `re` module flag names, e.g. `["IGNORECASE"]` |

### Template format

| Template value | Result |
|---|---|
| `"Person{n:03d}"` | `Person001`, `Person002`, … |
| `"person{n:03d}@anon.invalid"` | `person001@anon.invalid`, … |
| `"preserve_length"` | Counter zero-padded to the same width as the original |
| `"{orig_len}-char-{n}"` | Embeds original length, e.g. `7-char-1` |

> **TOML tip:** always use single quotes (`'...'`) for regex strings. Double-quoted strings in TOML process escape sequences, turning `\b` into a backspace character rather than a word boundary.

---

## How it works

1. The config is loaded and each `[[patterns]]` block is compiled into a `PatternDef`.
2. Each page / paragraph / cell of the document is scanned against all patterns in config order.
3. When a span is claimed by a pattern, no later pattern can overlap it — so `email` beats `name` for `John.Smith@example.com`.
4. Each unique original value is assigned exactly one pseudonym (stored in `PseudonymRegistry`). The same value always maps to the same pseudonym within a file.
5. The mapping is written to `_mapping.json` as `{ pseudonym: original }`.
6. De-anonymization reads the mapping and applies plain string replacements in longest-first order.

---

## Limitations

- **DOCX / ODT:** paragraph-level formatting (styles, spacing, alignment) is preserved. Per-run character formatting (bold/italic on individual words) may be collapsed within replaced spans.
- **PDF:** output is plain text. The anonymized file loses all layout and formatting.
- **Name detection without spaCy:** the title-case heuristic catches consecutive capitalized words, which can produce false positives in documents with many heading-style phrases. Install spaCy for significantly better accuracy.
- **Cross-cell PII:** a value split across multiple cells or paragraphs will not be detected. PII must appear within a single text unit.
- **No guarantee of completeness:** pseudo-anonymization is a best-effort process. Review the output and the stats before sharing a file.

---

## Running the tests

```bash
python3 -m pytest pseudo_anonymize_tests.py -v
```

116 tests covering templates, span overlap, exclusions, registry consistency, round-trip anonymization/de-anonymization for all file formats, and spaCy NER.

---

## Project structure

```
pseudo_anonymize.py              Main script
pseudo_anonymize_config.toml     Pattern definitions (edit this to extend)
pseudo_anonymize_tests.py        Test suite
README.md                        This file
```

---

## Disclaimer

This tool is provided as a convenience utility. It is **not** a certified anonymization or de-identification solution and makes no guarantees of completeness. Always review the anonymized output before sharing, especially in contexts subject to GDPR, HIPAA, or other data-protection regulations.

The direction and requirements were provided by the user; all code was generated by Claude (Anthropic). Developers should review and validate the script against their own data and requirements before relying on it in production.
