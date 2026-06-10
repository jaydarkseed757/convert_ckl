# ckl_convert.py

Converts DISA STIG Checklist files (`.ckl` / `.chk`) into **JSON**, **TOML**,
and **Markdown** formats. Designed for hardened RHEL 8 environments with zero
external dependencies — stdlib only.

---

## Requirements

- Python 3.6+
- No third-party packages — uses only `argparse`, `json`, `os`, `sys`,
  `xml.etree.ElementTree`, `datetime`, and `pathlib`

> **Testing only:** `pytest` is the sole external dependency and is only
> needed to run the test suite. It is not required to use `ckl_convert.py`.

---

## Usage

```bash
python3 ckl_convert.py INPUT_FILE [--run-as-root] [--report] [--prompt]
                       [--chunk N] [--quiet] [--output-dir DIR]
```

### Arguments

| Argument | Type | Description |
|---|---|---|
| `INPUT_FILE` | positional | Path to the `.ckl` or `.chk` checklist file |
| `--run-as-root` | flag | Bypass the root-execution block (see [Security](#security)) |
| `--report` | flag | Also write a plain-text `report_<name>.txt` summary of processing stats. The severity breakdown honours `SEVERITY_OVERRIDE` (overridden findings count under their overridden CAT level, annotated `[N overridden]`) |
| `--prompt [STYLE]` | optional | Also write a `prompt_<name>.md` with a genAI system prompt prepended to the Markdown, ready to paste into a chatbot. `STYLE` defaults to `analyst` if omitted (see table below) |
| `--chunk N` | integer | Also split the Markdown into files of N findings each (`<name>_chunk_001.md`, …) — useful for large STIGs that exceed an LLM's context window |
| `--quiet` | flag | Suppress `[INFO]` and `[WARNING]` messages; `[ERROR]` messages are always shown |
| `--output-dir DIR` | path | Write all output files to `DIR` instead of alongside the input (directory is created automatically if it does not exist) |

#### `--prompt` styles

| Style | Intended use | Output format |
|---|---|---|
| `analyst` | Open-ended Q&A with a compliance expert (default) | Free-form analysis |
| `poam` | Generate a Plan of Action & Milestones for open findings | CSV table — paste into Excel |
| `brief` | Executive briefing for leadership | Markdown tables/headings — paste into Word |
| `remediation` | Step-by-step fix guide for the SA doing the work | Structured per-finding sections |

### Examples

```bash
# Standard usage
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl

# Also emit a stats summary
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --report

# Generate a paste-ready genAI prompt file (default analyst style)
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --prompt

# Generate a CSV POA&M table prompt for Excel
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --prompt poam

# Generate a Word-ready executive briefing prompt
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --prompt brief

# Generate a technical remediation guide prompt
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --prompt remediation

# Split a large STIG into 20-finding chunks for LLM context limits
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --chunk 20

# Write all output to a specific directory, suppress informational output
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --output-dir /tmp/stig_out --quiet

# Override root block — document your reason in change control
sudo python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --run-as-root
```

### Output

By default, files are written to the **same directory as the input** (override with `--output-dir`):

```
U_RHEL_8_STIG.ckl   ← input
U_RHEL_8_STIG.json  ← fully nested, indented JSON
U_RHEL_8_STIG.toml  ← [asset] table + [[vulnerabilities]] array of tables
U_RHEL_8_STIG.md    ← asset list + summary table + detailed findings
```

Optional outputs (each flag is additive — the three core files are always written):

```
report_U_RHEL_8_STIG.txt      ← --report   : Status / Severity breakdown (counts + %)
prompt_U_RHEL_8_STIG.md       ← --prompt   : genAI system prompt + full Markdown
U_RHEL_8_STIG_chunk_001.md    ← --chunk N  : findings 1–N
U_RHEL_8_STIG_chunk_002.md                   findings N+1–2N  … etc.
```

---

## Output Format Details

### JSON

Fully nested and UTF-8 encoded with 2-space indentation. Top-level structure:

```json
{
  "source_file": "U_RHEL_8_STIG.ckl",
  "converted_at": "2026-05-27T03:21:22Z",
  "asset": {
    "HOST_NAME": "rhel8-prod-01",
    "HOST_IP": "10.0.0.42",
    ...
  },
  "vulnerabilities": [
    {
      "stig_data": {
        "Vuln_Num": "V-230221",
        "Severity": "high",
        "Rule_ID": "SV-230221r792832_rule",
        "CCI_REF": ["CCI-000366", "CCI-001230"]
      },
      "STATUS": "NotAFinding",
      "FINDING_DETAILS": "...",
      "COMMENTS": "...",
      "SEVERITY_OVERRIDE": "",
      "SEVERITY_JUSTIFICATION": ""
    }
  ]
}
```

> **Note:** Repeated `STIG_DATA` attributes (most commonly `CCI_REF`) are
> collected into a JSON array rather than silently overwriting each other.
> Downstream consumers should expect either a string or a list for these fields.

### TOML

Hand-serialised with no external library. Structure follows the TOML spec:
an `[asset]` table at the top, followed by a `[[vulnerabilities]]` array of
tables. Repeated attributes such as `CCI_REF` are emitted as TOML arrays.
All strings are properly escaped (backslashes, quotes, control characters).

```toml
[asset]
HOST_NAME = "rhel8-prod-01"
HOST_IP   = "10.0.0.42"

[[vulnerabilities]]
STATUS          = "NotAFinding"
FINDING_DETAILS = "Release is 8.6, fully supported."

[vulnerabilities.stig_data]
Vuln_Num = "V-230221"
Severity = "high"
CCI_REF  = ["CCI-000366", "CCI-001230"]
```

### Markdown

A human-readable report with three sections:

- **Asset Information** — all `<ASSET>` fields as a bullet list
- **Vulnerability Summary** — status counts and a condensed table of
  `Vuln_Num`, `Rule_ID`, `Severity`, and `Status`
- **Detailed Findings** — per-finding blocks with title, severity, status,
  finding details, and comments

---

## Security

### Root execution guard

The script calls `os.geteuid()` on startup and **exits with an error** if run
as UID 0 (root):

```
[SECURITY ERROR] This script must not be run as root (UID 0).
```

Running file-conversion utilities as root on a hardened host risks unintended
permission changes on sensitive STIG output and unnecessarily expands the
attack surface. If an operational requirement genuinely demands it, pass
`--run-as-root` and ensure the decision is captured in your change record.
A prominent warning is still printed to `stderr` when the flag is used.

---

## Input Validation

The following checks run before any XML is parsed. Each failure prints a
prefixed message to `stderr` and exits non-zero.

| Check | Condition | Severity |
|---|---|---|
| File exists | `Path.exists()` | `[ERROR]` — exits |
| Regular file | `Path.is_file()` | `[ERROR]` — exits |
| Read permission | `os.access(R_OK)` | `[ERROR]` — exits |
| Non-empty | `stat().st_size > 0` | `[ERROR]` — exits |
| Extension | `.ckl` or `.chk` | `[WARNING]` — continues |

---

## Error Handling

| Condition | Handler |
|---|---|
| Malformed XML | `ET.ParseError` → `[ERROR]` message, `sys.exit(1)` |
| No `<VULN>` nodes found | `[WARNING]` — output files still written |
| No `<ASSET>` node found | `[WARNING]` — output files still written |
| Write permission denied | `PermissionError` → `[ERROR]` message per file |
| General I/O failure | `IOError` → `[ERROR]` message per file |
| JSON serialisation failure | `TypeError`/`ValueError` → `[ERROR]`, returns exit code 1 |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All three output files written successfully |
| `1` | Fatal error (invalid input, parse failure, JSON serialisation error) |

---

## Data Extracted

### From `<ASSET>`

All child elements are captured generically — no hardcoded field list — so
any STIG profile's asset fields are preserved. Common fields include
`HOST_NAME`, `HOST_IP`, `HOST_MAC`, `HOST_FQDN`, `ROLE`, `ASSET_TYPE`,
`TARGET_KEY`, and `WEB_OR_DATABASE`.

### From each `<VULN>`

| Field | Source |
|---|---|
| `stig_data.*` | All `<STIG_DATA>` `VULN_ATTRIBUTE` / `ATTRIBUTE_DATA` pairs |
| `STATUS` | `<STATUS>` direct child |
| `FINDING_DETAILS` | `<FINDING_DETAILS>` direct child |
| `COMMENTS` | `<COMMENTS>` direct child |
| `SEVERITY_OVERRIDE` | `<SEVERITY_OVERRIDE>` direct child |
| `SEVERITY_JUSTIFICATION` | `<SEVERITY_JUSTIFICATION>` direct child |

Recognised `stig_data` keys include (but are not limited to): `Vuln_Num`,
`Severity`, `Group_Title`, `Rule_ID`, `Rule_Ver`, `Rule_Title`, `Vuln_Discuss`,
`Check_Content`, `Fix_Text`, `Mitigations`, `STIGRef`, `TargetKey`,
`STIG_UUID`, `CCI_REF`.

---

## Testing

The test suite uses [pytest](https://pytest.org) and covers all critical paths
with 57 tests across four files.

### Install pytest

```bash
pip install pytest
```

### Run the tests

```bash
# All tests
python3 -m pytest tests/ -v

# Individual test files
python3 -m pytest tests/test_validation.py -v   # validate_input()
python3 -m pytest tests/test_parsing.py -v      # parse_asset(), parse_vulnerabilities(), parse_ckl()
python3 -m pytest tests/test_root_guard.py -v   # check_root()
python3 -m pytest tests/test_integration.py -v  # full pipeline via main()
```

### Coverage areas

| Test file | Function(s) covered | Tests |
|---|---|---|
| `test_root_guard.py` | `check_root()` | 8 |
| `test_validation.py` | `validate_input()` | 14 |
| `test_parsing.py` | `parse_asset()`, `parse_vulnerabilities()`, `parse_ckl()` | 21 |
| `test_integration.py` | `main()` end-to-end pipeline | 14 |

---

## Platform Compatibility

The script is a single stdlib-only file with no compiled extensions or
third-party packages, so it runs unmodified across platforms and Python versions:

### RHEL / Linux

| RHEL Release | System Python | Status |
|---|---|---|
| RHEL 8 | 3.6 | ✅ Supported (original target) |
| RHEL 9 | 3.9 | ✅ Supported — no changes required |
| RHEL 10 | 3.12 | ✅ Supported — no changes required |

### macOS

| macOS Release | Status |
|---|---|
| macOS 25 | ✅ Verified by user testing |

### Windows

Not currently supported — `os.geteuid()` is Unix-only and will raise
`AttributeError` on Windows. Planned for a future release.

All stdlib modules used (`argparse`, `json`, `os`, `re`, `sys`,
`xml.etree.ElementTree`, `datetime`, `pathlib`) are present in every supported
version. No version-gated syntax is used. The `datetime.now(timezone.utc)` form
is used throughout, so there are no deprecation warnings on Python 3.12.

---

## Hardened Environment Notes

- No `pip install` required — drop the single script file onto the target host.
- Output files inherit the permissions of the directory they are written to;
  set `umask 0027` or tighter before running if the output contains sensitive
  findings.
- The script does not write to `/tmp`, spawn subprocesses, open network
  connections, or access any path outside the input file's directory.
- Compatible with RHEL 8 system Python (3.6) through Python 3.12+.
