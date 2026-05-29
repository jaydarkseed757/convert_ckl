# ckl_convert.py

Converts DISA STIG Checklist files (`.ckl` / `.chk`) into **JSON**, **TOML**,
and **Markdown** formats. Designed for hardened RHEL 8 environments with zero
external dependencies — stdlib only.

---

## Requirements

- Python 3.6+
- No third-party packages — uses only `argparse`, `json`, `os`, `sys`,
  `xml.etree.ElementTree`, `datetime`, and `pathlib`

---

## Usage

```bash
python3 ckl_convert.py INPUT_FILE [--run-as-root]
```

### Arguments

| Argument | Type | Description |
|---|---|---|
| `INPUT_FILE` | positional | Path to the `.ckl` or `.chk` checklist file |
| `--run-as-root` | flag | Bypass the root-execution block (see [Security](#security)) |

### Examples

```bash
# Standard usage
python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl

# Override root block — document your reason in change control
sudo python3 ckl_convert.py /path/to/U_RHEL_8_STIG.ckl --run-as-root
```

### Output

Three files are written to the **same directory as the input**, sharing its
base name:

```
U_RHEL_8_STIG.ckl   ← input
U_RHEL_8_STIG.json  ← fully nested, indented JSON
U_RHEL_8_STIG.toml  ← [asset] table + [[vulnerabilities]] array of tables
U_RHEL_8_STIG.md    ← asset list + summary table + detailed findings
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

## Hardened Environment Notes

- No `pip install` required — drop the single script file onto the target host.
- Output files inherit the permissions of the directory they are written to;
  set `umask 0027` or tighter before running if the output contains sensitive
  findings.
- The script does not write to `/tmp`, spawn subprocesses, open network
  connections, or access any path outside the input file's directory.
- Compatible with RHEL 8 system Python (3.6) through Python 3.12+.
