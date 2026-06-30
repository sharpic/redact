# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
python3 -m pytest redact_tests.py -v

# Run a single test
python3 -m pytest redact_tests.py -v -k "test_name_here"

# Run with coverage
python3 -m pytest redact_tests.py --cov=redact --cov-report=term-missing

# Check cyclomatic complexity
python3 -m radon cc -s -a redact.py

# CRAP scores (requires coverage.xml)
python3 .github/scripts/compute_crap.py

# Run the tool
python3 redact.py <input_file> [options]
python3 redact.py <input_file> --restore
```

## Architecture

The entire tool lives in a single file (`redact.py`) with no package structure. `redact_config.toml` is the only other file users need to touch.

### Data flow

```
redact_config.toml
       │ load_config() → build_patterns()
       ▼
  [PatternDef, ...]          ← compiled at startup; bad patterns fail early
       │
       ▼
  cmd_redact(args)
       │ _load_nlp()         ← optional spaCy; graceful fallback to regex
       │ PseudonymRegistry() ← one instance per run
       │ transform_fn = lambda text: redact_text(text, registry, patterns, nlp)
       │
       ▼
  _HANDLERS[suffix](input, output, transform_fn)
       │
       ▼
  _mapping.json + _redacted.<ext>
```

### Key components

**`PseudonymRegistry`** — keyed by `(pattern_name, stripped_original)`. Guarantees the same original always maps to the same pseudonym within a file run. The mapping file is `{pseudonym: original}` (reversed), enabling restoration.

**`redact_text`** — applies patterns in config order. First pattern to claim a character span wins; later patterns cannot overlap it. This is why `email` must be listed before `name` in the config — it prevents `John.Smith@example.com` being partially redacted as a name. Spans are applied in reverse offset order so earlier replacements don't invalidate later indices.

**`_HANDLERS`** — dispatch dict mapping file extension → `(handler_fn, output_ext, lib_name)`. Format-specific libraries (`python-docx`, `openpyxl`, etc.) are imported lazily inside each handler, so missing a library only fails on the relevant format.

**DOCX paragraph handling** — `_process_docx_para` concatenates all runs in a paragraph, transforms the combined string, then writes the result to `runs[0]` and clears the rest. This preserves paragraph-level formatting (styles, alignment) but collapses per-run character formatting (bold/italic) within any replaced span. This is an intentional trade-off.

**MCN mode (`-mcn`)** — xlsx-specific two-pass approach: prescan populates the registry with full names (by combining cells row-wise and header-aware), then a component-word fallback in `_xlsx_transform_cell` catches fragments (`"Alice"`, `"Johnson"`) in individual cells that NER wouldn't detect alone. Only applies to `.xlsx`.

## Error-handling conventions

- **Fatal user errors** → `sys.exit(f'Error: ...')`. Used for missing input files, unsupported formats, empty pattern config, missing mapping files.
- **Missing format libraries** → caught as `ImportError` at the top of `cmd_redact`/`cmd_restore` and converted to `sys.exit(f'Missing library — run: pip install {lib}')`. The lib name comes from `_HANDLERS`.
- **spaCy failures** → caught in `_load_nlp()` as `ImportError` or `OSError` and logged as `[info]` messages. The tool continues with the regex fallback. Never fatal.
- No custom exception classes; no re-raising.

## Gotchas

**Mocking handlers in tests** — `_HANDLERS` captures function references at import time. To simulate an `ImportError` from a handler, patch the dict entry directly:
```python
patch.dict('redact._HANDLERS', {'.docx': (bad_fn, '.docx', 'python-docx')})
```
Patching `redact.process_docx` has no effect because `_HANDLERS['.docx']` already holds the original reference.

**Pattern order matters** — patterns in `redact_config.toml` are applied in the order listed. The `email` pattern must precede `name` to avoid partial matches. The `proper_noun` pattern has `pn_only = true` and is filtered out unless `-pn` is passed.

**`restore_text` uses longest-first replacement** — ensures `person001@anon.invalid` is substituted before `person001`, preventing partial corruption of email pseudonyms.

**PDF output is always plain text** — the handler writes `.txt` regardless of input; output extension comes from `_HANDLERS`, not the input suffix.

**`pragma: no cover`** — the `if __name__ == '__main__':` guard is excluded from coverage. Don't remove this marker.

## Adding patterns

Edit `redact_config.toml` only — no Python changes needed. Always use single-quoted strings for regex values in TOML (`'\b...\b'`); double-quoted strings process escape sequences and silently break word-boundary anchors. New patterns are compiled at startup; a bad regex raises immediately rather than failing mid-document.
