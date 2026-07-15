# CLAUDE.md

Guidance for working in this repository.

## Overview

Two standalone Python CLI tools that convert DISA STIG Checklist files
(`.ckl` / `.chk`, which are XML) into other formats:

- **`ckl_convert.py`** — converts one or more checklists to **JSON**, **TOML**,
  and **Markdown** at once. Opt-in extras: `--report`, `--prompt`, `--chunk`,
  `--quiet`, `--output-dir`, `--open-only`, `--severity`, `--summary`,
  `--diff OLD_CKL`.
- **`ckl2csv.py`** — converts a checklist to a single flat **CSV**
  (one row per finding). Supports `--open-only` / `--severity`. Fully
  self-contained; does **not** import `ckl_convert.py`.

Primary downstream use: the Markdown/`--prompt` output is fed into a Gemini
chatbot on genai.mil; the CSV feeds Excel/POA&M workflows.

## Hard constraints

- **Stdlib only.** No third-party runtime dependencies, ever. Both scripts use
  only `argparse`, `json`, `os`, `re`, `sys`, `csv`, `xml.etree.ElementTree`,
  `datetime`, `pathlib`. `pytest` is the *only* external package and is used
  *solely* for the test suite — never required to run the tools.
- **Python 3.6+** compatibility. No walrus, no `match`, no `|` union types, no
  f-string features newer than 3.6. Verified to run unmodified on RHEL 8 (3.6),
  RHEL 9 (3.9), RHEL 10 (3.12), and macOS 25.
- **`ckl2csv.py` stays standalone.** It intentionally duplicates the root
  guard / validation / XML-parsing patterns inline rather than importing from
  `ckl_convert.py`, so it can be copied to a host as a single file. Do not
  refactor the two into a shared module.
- **Windows is not yet supported** (deferred). `os.geteuid()` in the root guard
  is Unix-only. Don't claim Windows support without guarding that call.

## Conventions

- **Root guard:** both scripts refuse to run as UID 0 unless `--run-as-root`
  is passed. In this container you run as root, so pass `--run-as-root` for
  manual runs.
- **Quiet contract:** `--quiet` suppresses `[INFO]`/`[WARNING]`/`[OK]` via the
  `_info()` / `_warn()` helpers. `[ERROR]` messages always print (plain
  `print(..., file=sys.stderr)`), and the `[SECURITY …]` root-guard messages
  are also always shown.
- **Repeated `STIG_DATA` attributes** (commonly `CCI_REF`) are collected into a
  **list**, never overwritten. Downstream code must handle str-or-list:
  JSON/TOML emit arrays; Markdown/CSV join them (`, ` and `; ` respectively).
- **`SEVERITY_OVERRIDE`** takes precedence over raw `Severity` everywhere an
  "effective severity" is needed (`build_report()` breakdown, `--severity`
  filtering). The report's `[N overridden]` annotation appears only when the
  override actually differs from the original (some exporters echo Severity
  into SEVERITY_OVERRIDE).
- **Filters** (`--open-only`, `--severity`) apply to every written output and
  emit an `[INFO] Filters applied ...: N findings -> M` provenance line.
  Exception: `--diff` always compares unfiltered data — a filter must never
  hide a remediated or newly-open finding from the delta.
- **Batch input** (`ckl_convert.py` only): multiple INPUT_FILEs are converted
  independently; a failed file doesn't stop the rest (main() catches the
  SystemExit from validate_input/parse_ckl per file). Exit 0 only when every
  file succeeded. `--diff` requires exactly one INPUT_FILE.
- **`--summary`** prints `build_report()` to stdout and writes nothing; the
  report prints even under `--quiet` (it is the requested output, not chrome).
- Output files are written next to the input (same stem) unless redirected
  (`--output-dir` for `ckl_convert.py`, `-o` for `ckl2csv.py`).
- Free-text fields (`FINDING_DETAILS`, `COMMENTS`) render as Markdown
  blockquotes so embedded `#`/`---`/`|` can't alter document structure.
  TOML/CSV rely on proper escaping (hand-rolled for TOML, the `csv` module
  for CSV).

## Tests

- `python3 -m pytest tests/ -q` — 290 tests, all should pass.
- Only `ckl_convert.py` is covered by the suite; `ckl2csv.py` is verified
  manually (no pytest file by design).
- Shared fixtures live in `tests/fixtures/`: `valid.ckl` (3 findings),
  `minimal.ckl` (1), `malformed.ckl` (invalid XML), `rhel8_stig.ckl`
  (realistic 15-finding RHEL 8 STIG V1R13, includes a severity override on
  V-230223).
- `tests/conftest.py` loads the module under test via `importlib` and exposes
  `copy_fixture` / `run_main` helpers plus the `ckl_module` / `fixtures_dir`
  fixtures. Test files import helpers as `from tests.conftest import ...`.
- When a fixture's counts change, update the module-level constants at the top
  of `tests/test_rhel8_fixture.py` (e.g. `REPORT_CAT_I_COUNT`).

## Git workflow

- Work on a feature/fix branch, open a PR, merge to `main` via the GitHub MCP
  tools. Do not push directly to `main` (the auto-mode classifier blocks it).
- Commit only when asked. This container is ephemeral — push anything worth
  keeping.
