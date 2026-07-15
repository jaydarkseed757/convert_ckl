#!/usr/bin/env python3
"""
ckl_convert.py — DISA STIG Checklist (.ckl / .chk) converter
Converts STIG Checklist XML files to JSON, TOML, and Markdown.

Requirements:
  - Python 3.6+
  - Zero external dependencies (stdlib only)
  - Must NOT be run as root (unless --run-as-root is passed)

Usage:
  python3 ckl_convert.py <input_file.ckl> [--run-as-root]
"""

import argparse
import csv
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_EXTENSIONS = {".ckl", ".chk"}


# ---------------------------------------------------------------------------
# Quiet-mode helpers
# ---------------------------------------------------------------------------

_quiet: bool = False   # set to True by --quiet in main()


def _info(msg: str) -> None:
    if not _quiet:
        print(msg)


def _warn(msg: str) -> None:
    if not _quiet:
        print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Root guard
# ---------------------------------------------------------------------------

def check_root(allow_root: bool) -> None:
    """Block execution as root unless explicitly overridden."""
    if not hasattr(os, "geteuid"):
        # Windows has no UID concept; the guard does not apply there.
        return
    if os.geteuid() == 0:
        if allow_root:
            print(
                "[SECURITY WARNING] Running as root is strongly discouraged. "
                "Proceeding because --run-as-root was passed.",
                file=sys.stderr,
            )
        else:
            print(
                "[SECURITY ERROR] This script must not be run as root (UID 0).\n"
                "Running conversion utilities as root can expose sensitive STIG "
                "data to unintended file-permission changes and increases attack "
                "surface on a hardened host.\n"
                "If you understand the risk and must proceed, re-run with: "
                "--run-as-root",
                file=sys.stderr,
            )
            sys.exit(1)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def validate_input(path: str) -> Path:
    """
    Validate the input file path.  Returns a resolved Path on success;
    prints a descriptive error and exits on failure.
    """
    p = Path(path)

    if not p.exists():
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    if not p.is_file():
        print(f"[ERROR] Path is not a regular file: {path}", file=sys.stderr)
        sys.exit(1)

    # os.access() on Windows only checks the read-only attribute, not NTFS
    # ACLs, so probe with a real open there; keep os.access on POSIX.
    if sys.platform == "win32":
        try:
            with p.open("rb"):
                pass
        except OSError:
            print(f"[ERROR] No read permission on file: {path}", file=sys.stderr)
            sys.exit(1)
    elif not os.access(p, os.R_OK):
        print(f"[ERROR] No read permission on file: {path}", file=sys.stderr)
        sys.exit(1)

    if p.stat().st_size == 0:
        print(f"[ERROR] File is empty: {path}", file=sys.stderr)
        sys.exit(1)

    if p.suffix.lower() not in VALID_EXTENSIONS:
        _warn(
            f"[WARNING] Unexpected file extension '{p.suffix}'. "
            f"Expected one of {sorted(VALID_EXTENSIONS)}. Attempting to parse anyway."
        )

    return p.resolve()


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def parse_asset(root: ET.Element) -> dict:
    """Extract all child elements of the <ASSET> node into a flat dict."""
    asset = {}
    asset_node = root.find(".//ASSET")
    if asset_node is not None:
        for child in asset_node:
            asset[child.tag] = (child.text or "").strip()
    return asset


def parse_vulnerabilities(root: ET.Element) -> list:
    """
    Extract every <VULN> node.  For each vuln, collect:
      - All <STIG_DATA> key/value pairs  (Vuln_Attribute → Attribute_Data)
      - STATUS, FINDING_DETAILS, COMMENTS, SEVERITY_OVERRIDE, SEVERITY_JUSTIFICATION
    """
    vulns = []

    for vuln_node in root.findall(".//VULN"):
        entry: dict = {}

        # --- STIG_DATA children -------------------------------------------------
        # A given VULN_ATTRIBUTE can legitimately appear more than once
        # (CCI_REF is the common case). Collect repeats into a list rather
        # than letting the later value silently overwrite the earlier one.
        stig_data: dict = {}
        for sd in vuln_node.findall("STIG_DATA"):
            attr_name  = sd.findtext("VULN_ATTRIBUTE", default="").strip()
            attr_value = sd.findtext("ATTRIBUTE_DATA", default="").strip()
            if not attr_name:
                continue
            if attr_name in stig_data:
                existing = stig_data[attr_name]
                if isinstance(existing, list):
                    existing.append(attr_value)
                else:
                    stig_data[attr_name] = [existing, attr_value]
            else:
                stig_data[attr_name] = attr_value
        entry["stig_data"] = stig_data

        # --- Direct children we always want ------------------------------------
        for tag in ("STATUS", "FINDING_DETAILS", "COMMENTS",
                    "SEVERITY_OVERRIDE", "SEVERITY_JUSTIFICATION"):
            entry[tag] = (vuln_node.findtext(tag) or "").strip()

        vulns.append(entry)

    return vulns


def parse_ckl(filepath: Path) -> dict:
    """
    Parse the CKL/CHK XML file.  Returns a dict with keys:
      'asset'           -> dict of asset metadata
      'vulnerabilities' -> list of vuln dicts
      'source_file'     -> str filename
      'converted_at'    -> ISO-8601 timestamp
    """
    try:
        tree = ET.parse(str(filepath))
    except (ET.ParseError, OSError) as exc:
        print(f"[ERROR] XML parse error in '{filepath}': {exc}", file=sys.stderr)
        sys.exit(1)

    root = tree.getroot()
    asset  = parse_asset(root)
    vulns  = parse_vulnerabilities(root)

    return {
        "source_file":   filepath.name,
        "converted_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "asset":         asset,
        "vulnerabilities": vulns,
    }


# ---------------------------------------------------------------------------
# TOML serialisation (hand-rolled, no external deps)
# ---------------------------------------------------------------------------

def _toml_escape_string(value: str) -> str:
    """
    Escape a Python string for use inside TOML basic double-quoted strings.
    Handles backslashes, double-quotes, and common control characters.
    """
    # Order matters: escape backslash first so we don't double-escape later.
    value = value.replace("\\", "\\\\")
    value = value.replace('"',  '\\"')
    value = value.replace("\b", "\\b")
    value = value.replace("\f", "\\f")
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "\\r")
    value = value.replace("\t", "\\t")
    # Remaining C0 control chars and DEL have no named TOML escape; use \uXXXX.
    value = re.sub(r"[\x00-\x07\x0b\x0e-\x1f\x7f]",
                   lambda m: f"\\u{ord(m.group()):04X}", value)
    return value


# Valid TOML bare-key characters; anything else forces a quoted key.
_BARE_KEY_RE = re.compile(r"[A-Za-z0-9_-]+")


def _toml_kv(key: str, value) -> str:
    """
    Return a single TOML `key = value` line.

    A string value is emitted as a quoted basic string; a list value is
    emitted as a TOML array of quoted strings (this is how repeated
    STIG_DATA attributes such as CCI_REF are represented).

    Keys that are not valid TOML bare keys (A-Z a-z 0-9 - _) are quoted
    so that dots or other characters are not misread as dotted-key syntax.
    """
    safe_key = key if _BARE_KEY_RE.fullmatch(key) else f'"{_toml_escape_string(key)}"'
    if isinstance(value, list):
        items = ", ".join(f'"{_toml_escape_string(str(v))}"' for v in value)
        return f"{safe_key} = [{items}]"
    return f'{safe_key} = "{_toml_escape_string(str(value))}"'


def build_toml(data: dict) -> str:
    """
    Manually construct a TOML document from the parsed CKL data.

    Structure:
      # header comment
      source_file = "..."
      converted_at = "..."

      [asset]
      HOST_NAME = "..."
      ...

      [[vulnerabilities]]
      STATUS = "..."
      ...

      [vulnerabilities.stig_data]
      Vuln_Num = "..."
      ...
    """
    lines: list = []

    # --- File-level header ---------------------------------------------------
    lines.append("# DISA STIG Checklist — converted by ckl_convert.py")
    lines.append(f'# Source : {_toml_escape_string(data["source_file"])}')
    lines.append(f'# Generated : {data["converted_at"]}')
    lines.append("")
    lines.append(_toml_kv("source_file",  data["source_file"]))
    lines.append(_toml_kv("converted_at", data["converted_at"]))
    lines.append("")

    # --- [asset] table -------------------------------------------------------
    lines.append("[asset]")
    for k, v in sorted(data["asset"].items()):
        lines.append(_toml_kv(k, v))
    lines.append("")

    # --- [[vulnerabilities]] array of tables ---------------------------------
    for vuln in data["vulnerabilities"]:
        lines.append("[[vulnerabilities]]")

        # Top-level fields first (STATUS, FINDING_DETAILS, etc.)
        for field in ("STATUS", "FINDING_DETAILS", "COMMENTS",
                      "SEVERITY_OVERRIDE", "SEVERITY_JUSTIFICATION"):
            lines.append(_toml_kv(field, vuln.get(field, "")))

        # Nested stig_data as a sub-table. Emit it LAST so that every
        # preceding key binds to the [[vulnerabilities]] table, not to the
        # sub-table. Skip the header entirely when there is no data.
        stig_data = vuln.get("stig_data", {})
        if stig_data:
            lines.append("")
            lines.append("[vulnerabilities.stig_data]")
            for k, v in stig_data.items():
                lines.append(_toml_kv(k, v))

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown generation
# ---------------------------------------------------------------------------

def _md_escape(text) -> str:
    """
    Escape pipe characters so they don't break Markdown tables, and collapse
    newlines to spaces for safe inline/table rendering. Accepts a list (joins
    with ', ') so repeated STIG_DATA values render cleanly.
    """
    if isinstance(text, list):
        text = ", ".join(str(t) for t in text)
    else:
        text = str(text)
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _display_host(asset: dict) -> str:
    """Best-available host identifier for titles and report headers."""
    return asset.get("HOST_NAME") or asset.get("ASSET_NAME") or "Unknown Host"


def _count_statuses(vulns: list) -> dict:
    """Count findings by STATUS; missing or empty status counts as 'Unknown'."""
    counts: dict = {}
    for v in vulns:
        s = v.get("STATUS") or "Unknown"
        counts[s] = counts.get(s, 0) + 1
    return counts


# Statuses that represent findings still needing action.
OPEN_STATUSES = ("Open", "Not_Reviewed")


def _effective_severity(vuln: dict) -> str:
    """Severity used for filtering/reporting: the override wins when set."""
    return ((vuln.get("SEVERITY_OVERRIDE") or
             vuln.get("stig_data", {}).get("Severity") or "").strip().lower())


def filter_vulnerabilities(vulns: list, open_only: bool = False,
                           severities: set = None) -> list:
    """
    Return the subset of vulns matching the active filters.

    open_only  — keep only findings whose STATUS is in OPEN_STATUSES.
    severities — keep only findings whose effective severity (override-aware)
                 is in the given set of lowercase levels, e.g. {"high", "medium"}.
    """
    out = vulns
    if open_only:
        out = [v for v in out if v.get("STATUS") in OPEN_STATUSES]
    if severities:
        out = [v for v in out if _effective_severity(v) in severities]
    return out


def build_markdown(data: dict) -> str:
    """
    Build a Markdown document with:
      - A title block
      - Asset metadata as a definition list
      - A summary table of vulnerabilities
    """
    lines: list = []

    asset = data["asset"]
    host  = _display_host(asset)

    # --- Title ---------------------------------------------------------------
    lines.append(f"# STIG Checklist Report — {_md_escape(host)}")
    lines.append("")
    lines.append(f"**Source file:** `{data['source_file']}`  ")
    lines.append(f"**Converted:** {data['converted_at']}  ")
    lines.append("")

    # --- Asset information ---------------------------------------------------
    lines.append("## Asset Information")
    lines.append("")
    if asset:
        for k, v in sorted(asset.items()):
            display_v = v if v else "_not set_"
            lines.append(f"- **{k}:** {_md_escape(display_v)}")
    else:
        lines.append("_No asset data found._")
    lines.append("")

    # --- Vulnerability summary table -----------------------------------------
    lines.append("## Vulnerability Summary")
    lines.append("")

    vulns = data["vulnerabilities"]
    if not vulns:
        lines.append("_No vulnerabilities found._")
    else:
        status_counts = _count_statuses(vulns)

        lines.append(f"**Total findings:** {len(vulns)}  ")
        for status, count in sorted(status_counts.items()):
            lines.append(f"- {status}: {count}")
        lines.append("")

        # Table header
        lines.append("| Vuln_Num | Rule_ID | Severity | Status |")
        lines.append("|----------|---------|----------|--------|")

        for vuln in vulns:
            sd = vuln.get("stig_data", {})
            vuln_num = _md_escape(sd.get("Vuln_Num", ""))
            rule_id  = _md_escape(sd.get("Rule_ID",  ""))
            severity = _md_escape(sd.get("Severity", ""))
            status   = _md_escape(vuln.get("STATUS", ""))
            lines.append(f"| {vuln_num} | {rule_id} | {severity} | {status} |")

    lines.append("")

    # --- Detailed findings ---------------------------------------------------
    lines.append("## Detailed Findings")
    lines.append("")

    for i, vuln in enumerate(vulns, start=1):
        sd       = vuln.get("stig_data", {})
        vuln_num = sd.get("Vuln_Num", f"VULN-{i}")
        rule_id  = sd.get("Rule_ID",  "N/A")
        title    = sd.get("Rule_Title", "")
        severity = sd.get("Severity",  "")
        status   = vuln.get("STATUS",  "")

        lines.append(f"### {_md_escape(vuln_num)} — {_md_escape(rule_id)}")
        lines.append("")
        if title:
            lines.append(f"**Title:** {_md_escape(title)}  ")
        lines.append(f"**Severity:** {_md_escape(severity)}  ")
        lines.append(f"**Status:** {_md_escape(status)}  ")

        # Render free-text blocks as blockquotes so embedded Markdown syntax
        # (#, ---, |) in checklist content cannot alter the document structure.
        finding = vuln.get("FINDING_DETAILS", "").strip()
        if finding:
            lines.append("")
            lines.append("**Finding Details:**")
            lines.append("")
            lines.extend(f"> {ln}" for ln in finding.splitlines())

        comments = vuln.get("COMMENTS", "").strip()
        if comments:
            lines.append("")
            lines.append("**Comments:**")
            lines.append("")
            lines.extend(f"> {ln}" for ln in comments.splitlines())

        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Plain-text processing report
# ---------------------------------------------------------------------------

# STIG severity → DISA category label
_SEVERITY_LABELS = {
    "high":   "CAT I (high)",
    "medium": "CAT II (medium)",
    "low":    "CAT III (low)",
}


def build_report(data: dict) -> str:
    """
    Build a plain-text summary of what was processed: a short header plus a
    Status breakdown and a Severity breakdown (counts and percentages).
    """
    asset = data["asset"]
    host  = _display_host(asset)
    vulns = data["vulnerabilities"]
    total = len(vulns)

    def _pct(count: int) -> str:
        return f"{100.0 * count / total:.1f}" if total else "0.0"

    lines: list = []
    lines.append("=" * 50)
    lines.append(" STIG Checklist Processing Report")
    lines.append("=" * 50)
    lines.append(f"Source file    : {data['source_file']}")
    lines.append(f"Host           : {host}")
    lines.append(f"Generated      : {data['converted_at']}")
    lines.append(f"Total findings : {total}")
    lines.append("")

    # --- Status breakdown ----------------------------------------------------
    lines.append("Status Breakdown")
    lines.append("-" * 16)
    if not vulns:
        lines.append("(none)")
    else:
        status_counts = _count_statuses(vulns)
        for status, count in sorted(status_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"{status:<18} {count:>4}  ({_pct(count)}%)")
    lines.append("")

    # --- Severity breakdown --------------------------------------------------
    lines.append("Severity Breakdown")
    lines.append("-" * 18)
    if not vulns:
        lines.append("(none)")
    else:
        # A SEVERITY_OVERRIDE recategorises a finding (e.g. high → medium with
        # documented justification), so it takes precedence over the raw Severity.
        sev_counts: dict = {}
        override_counts: dict = {}
        for v in vulns:
            original = (v.get("stig_data", {}).get("Severity") or "").strip().lower()
            override = (v.get("SEVERITY_OVERRIDE") or "").strip().lower()
            raw = override or original
            label = _SEVERITY_LABELS.get(raw, f"Other ({raw})" if raw else "Unspecified")
            sev_counts[label] = sev_counts.get(label, 0) + 1
            # Only an override that actually changes the category counts as
            # overridden — some exporters echo Severity into SEVERITY_OVERRIDE.
            if override and override != original:
                override_counts[label] = override_counts.get(label, 0) + 1

        def _sev_line(label: str, count: int) -> str:
            line = f"{label:<18} {count:>4}  ({_pct(count)}%)"
            overridden = override_counts.get(label, 0)
            if overridden:
                line += f"  [{overridden} overridden]"
            return line

        # Order: CAT I, II, III first (in that order), then any extras by count desc.
        ordered = [_SEVERITY_LABELS["high"], _SEVERITY_LABELS["medium"], _SEVERITY_LABELS["low"]]
        seen = set()
        for label in ordered:
            if label in sev_counts:
                seen.add(label)
                lines.append(_sev_line(label, sev_counts[label]))
        for label, count in sorted((kv for kv in sev_counts.items() if kv[0] not in seen),
                                   key=lambda kv: (-kv[1], kv[0])):
            lines.append(_sev_line(label, count))
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Checklist diff (remediation delta between two scans)
# ---------------------------------------------------------------------------

def _vuln_key(vuln: dict, index: int) -> str:
    """Stable matching key for a finding: Vuln_Num, else Rule_ID, else position."""
    sd = vuln.get("stig_data", {})
    return sd.get("Vuln_Num") or sd.get("Rule_ID") or f"(unkeyed #{index})"


def _diff_row(vuln: dict, old_status: str, new_status: str) -> str:
    sd = vuln.get("stig_data", {})
    return (f"| {_md_escape(sd.get('Vuln_Num', ''))} "
            f"| {_md_escape(sd.get('Rule_Title', ''))} "
            f"| {_md_escape(_effective_severity(vuln))} "
            f"| {_md_escape(old_status)} | {_md_escape(new_status)} |")


def build_diff(old_data: dict, new_data: dict) -> str:
    """
    Build a Markdown delta report between two scans of the same target.

    Findings are matched by Vuln_Num (falling back to Rule_ID). Sections:
      Newly Open     — open in NEW; was closed in OLD or absent from OLD
      Remediated     — closed in NEW; was open in OLD
      Status Changed — present in both with any other status transition
      Added          — only in NEW (and not open, else it is Newly Open)
      Removed        — only in OLD
    Always runs on unfiltered data so remediated findings can't be hidden.
    """
    old_by_key = {_vuln_key(v, i): v for i, v in enumerate(old_data["vulnerabilities"])}
    new_by_key = {_vuln_key(v, i): v for i, v in enumerate(new_data["vulnerabilities"])}

    newly_open, remediated, changed, added, removed = [], [], [], [], []
    unchanged = 0

    for key, new_v in new_by_key.items():
        new_status = new_v.get("STATUS", "")
        old_v = old_by_key.get(key)
        if old_v is None:
            if new_status in OPEN_STATUSES:
                newly_open.append(_diff_row(new_v, "(not in old file)", new_status))
            else:
                added.append(_diff_row(new_v, "(not in old file)", new_status))
            continue
        old_status = old_v.get("STATUS", "")
        if old_status == new_status:
            unchanged += 1
        elif new_status in OPEN_STATUSES and old_status not in OPEN_STATUSES:
            newly_open.append(_diff_row(new_v, old_status, new_status))
        elif old_status in OPEN_STATUSES and new_status not in OPEN_STATUSES:
            remediated.append(_diff_row(new_v, old_status, new_status))
        else:
            changed.append(_diff_row(new_v, old_status, new_status))

    for key, old_v in old_by_key.items():
        if key not in new_by_key:
            removed.append(_diff_row(old_v, old_v.get("STATUS", ""), "(not in new file)"))

    lines: list = []
    lines.append(f"# STIG Checklist Diff — {_md_escape(new_data['source_file'])} "
                 f"vs {_md_escape(old_data['source_file'])}")
    lines.append("")
    lines.append(f"**Old:** `{old_data['source_file']}`  ")
    lines.append(f"**New:** `{new_data['source_file']}`  ")
    lines.append("")
    lines.append(f"**Summary:** {len(newly_open)} newly open, {len(remediated)} remediated, "
                 f"{len(changed)} status changed, {len(added)} added, "
                 f"{len(removed)} removed, {unchanged} unchanged")
    lines.append("")

    table_header = ("| Vuln_Num | Rule_Title | Severity | Old Status | New Status |",
                    "|----------|------------|----------|------------|------------|")

    for title, rows in (("Newly Open", newly_open),
                        ("Remediated", remediated),
                        ("Status Changed", changed),
                        ("Added", added),
                        ("Removed", removed)):
        lines.append(f"## {title} ({len(rows)})")
        lines.append("")
        if rows:
            lines.extend(table_header)
            lines.extend(rows)
        else:
            lines.append("_None._")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV generation (kept in sync with the standalone ckl2csv.py by hand)
# ---------------------------------------------------------------------------

CSV_HEADER = [
    "Host_Name", "Host_IP",
    "Vuln_Num", "Severity", "Rule_ID", "Rule_Title", "CCI_REF",
    "Status", "Finding_Details", "Comments",
    "Severity_Override", "Severity_Justification",
]


def _field(value) -> str:
    """Join list-valued STIG_DATA attributes (e.g. repeated CCI_REF); pass through strings."""
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    return str(value) if value is not None else ""


def build_csv_rows(data: dict):
    """Return (header, rows) — one row per vulnerability, asset fields repeated."""
    asset    = data["asset"]
    host     = asset.get("HOST_NAME") or asset.get("ASSET_NAME") or ""
    host_ip  = asset.get("HOST_IP", "")

    rows = []
    for vuln in data["vulnerabilities"]:
        sd = vuln.get("stig_data", {})
        rows.append([
            host,
            host_ip,
            _field(sd.get("Vuln_Num", "")),
            _field(sd.get("Severity", "")),
            _field(sd.get("Rule_ID", "")),
            _field(sd.get("Rule_Title", "")),
            _field(sd.get("CCI_REF", "")),
            _field(vuln.get("STATUS", "")),
            _field(vuln.get("FINDING_DETAILS", "")),
            _field(vuln.get("COMMENTS", "")),
            _field(vuln.get("SEVERITY_OVERRIDE", "")),
            _field(vuln.get("SEVERITY_JUSTIFICATION", "")),
        ])

    return CSV_HEADER, rows


def write_csv(path: Path, header: list, rows: list) -> bool:
    """Write header + rows to path as CSV. Returns True on success."""
    try:
        # newline="" per the csv module docs: avoids extra blank lines on Windows.
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
        _info(f"[OK] CSV written → {path}")
        return True
    except PermissionError as exc:
        print(f"[ERROR] Permission denied writing CSV to '{path}': {exc}", file=sys.stderr)
        return False
    except IOError as exc:
        print(f"[ERROR] I/O error writing CSV to '{path}': {exc}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# GenAI prompt wrapper
# ---------------------------------------------------------------------------

_PROMPT_ANALYST = """\
You are a STIG compliance analyst reviewing an active DISA STIG security checklist.
The checklist below contains vulnerability findings for the specified host.
Your role is to help analyse findings, prioritise remediation efforts, identify common
root causes, and answer questions about compliance status and mitigation strategies.

Base all remediation guidance on the check and fix text provided in the checklist.
Focus on Open and Not_Reviewed findings as the highest-priority items.
"""

_PROMPT_POAM = """\
You are a STIG compliance analyst. Using the DISA STIG checklist below, produce a
Plan of Action & Milestones (POA&M) table for all Open and Not_Reviewed findings.

Output the table in CSV format with exactly these columns:
Weakness,Asset,CAT Level,Vuln_Num,Rule_ID,Finding Details,Recommended Mitigation,POC,Scheduled Completion Date,Status

Rules:
- CAT Level: CAT I for high, CAT II for medium, CAT III for low severity
- Leave POC and Scheduled Completion Date blank for the user to fill in
- Wrap any field containing commas or newlines in double quotes
- Include a header row
- Include only Open and Not_Reviewed findings; skip NotAFinding and Not Applicable
"""

_PROMPT_BRIEF = """\
You are a STIG compliance analyst preparing an executive briefing for leadership.
Using the DISA STIG checklist below, produce a Word-ready briefing document with
the following structure:

1. Executive Summary (2-3 sentences: host, total findings, most critical items)
2. Findings Overview Table (columns: CAT Level | Count | Percentage of Total)
3. Open Findings Table (columns: Vuln_Num | Title | Severity | Status | One-line Summary)
4. Top Priorities (the 3-5 most critical open findings, each with a single action item)
5. Recommended Next Steps (bulleted list)

Use Markdown headings and tables. Keep language accessible to a non-technical audience.
"""

_PROMPT_REMEDIATION = """\
You are a STIG system administrator preparing a technical remediation guide.
Using the DISA STIG checklist below, produce a step-by-step remediation guide
for all Open and Not_Reviewed findings.

For each finding, produce a section with:
- Finding ID and title
- Severity and current status
- What was found (from Finding Details)
- Exact commands or configuration file changes to remediate
- How to verify the fix is in place

Order findings by severity (CAT I first), then by Vuln_Num within each category.
Skip NotAFinding and Not Applicable entries entirely. Be specific and actionable.
"""

_PROMPT_TEMPLATES: dict = {
    "analyst":     _PROMPT_ANALYST,
    "poam":        _PROMPT_POAM,
    "brief":       _PROMPT_BRIEF,
    "remediation": _PROMPT_REMEDIATION,
}

PROMPT_STYLES = sorted(_PROMPT_TEMPLATES)


def build_prompt_md(data: dict, style: str = "analyst", md_content: str = None) -> str:
    """
    Return the chosen genAI prompt template prepended to the Markdown output.
    Pass an already-rendered md_content to avoid re-rendering the document.
    """
    template = _PROMPT_TEMPLATES.get(style, _PROMPT_ANALYST)
    if md_content is None:
        md_content = build_markdown(data)
    return template + "\n---\n\n" + md_content


# ---------------------------------------------------------------------------
# File writing helpers
# ---------------------------------------------------------------------------

def write_file(path: Path, content: str, label: str) -> bool:
    """Write content to path with error handling. Returns True on success."""
    try:
        path.write_text(content, encoding="utf-8")
        _info(f"[OK] {label} written → {path}")
        return True
    except PermissionError as exc:
        print(f"[ERROR] Permission denied writing {label} to '{path}': {exc}",
              file=sys.stderr)
        return False
    except IOError as exc:
        print(f"[ERROR] I/O error writing {label} to '{path}': {exc}",
              file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ckl_convert.py",
        description=(
            "Convert a DISA STIG Checklist (.ckl/.chk) to JSON, TOML, and Markdown.\n"
            "Stdlib-only — zero external dependencies.\n"
            "Designed for hardened RHEL 8 environments."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input_file",
        metavar="INPUT_FILE",
        nargs="+",
        help="Path(s) to STIG Checklist file(s) (.ckl or .chk). "
             "Multiple files are converted one after another.",
    )
    parser.add_argument(
        "--open-only",
        dest="open_only",
        action="store_true",
        default=False,
        help="Only include findings with status Open or Not_Reviewed in all outputs.",
    )
    parser.add_argument(
        "--severity",
        metavar="LEVELS",
        default=None,
        help="Comma-separated severity filter (high,medium,low). Uses the "
             "effective severity: SEVERITY_OVERRIDE when set, else Severity.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        default=False,
        help="Print the processing report to stdout and write NO files. "
             "Respects --open-only/--severity; other output flags are ignored.",
    )
    parser.add_argument(
        "--diff",
        metavar="OLD_CKL",
        default=None,
        help="Compare against an older checklist and also write diff_<name>.md "
             "(newly open / remediated / status changed / added / removed). "
             "The diff always uses unfiltered data. Single INPUT_FILE only.",
    )
    parser.add_argument(
        "--run-as-root",
        action="store_true",
        default=False,
        help=(
            "Bypass the root-execution block. "
            "Use only if you have a documented operational need and understand the risk."
        ),
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        default=False,
        help="Also write a flat <name>.csv, one row per finding "
             "(same format as the standalone ckl2csv.py).",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        default=False,
        help="Also write a plain-text report_<name>.txt summary of processing stats.",
    )
    parser.add_argument(
        "--prompt",
        nargs="?",
        const="analyst",
        default=None,
        metavar="STYLE",
        choices=PROMPT_STYLES,
        help=(
            "Also write a prompt_<name>.md with a genAI system prompt prepended to the Markdown. "
            f"STYLE is one of: {', '.join(PROMPT_STYLES)} (default: analyst). "
            "analyst=open-ended Q&A; poam=CSV POA&M table; "
            "brief=Word-ready executive briefing; remediation=technical fix guide."
        ),
    )
    parser.add_argument(
        "--chunk",
        type=int,
        metavar="N",
        default=None,
        help="Also split the Markdown into chunks of N findings each (<name>_chunk_001.md, ...).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress [INFO] and [WARNING] messages. [ERROR] messages are always shown.",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        metavar="DIR",
        default=None,
        help="Write all output files to DIR (created automatically if it does not exist).",
    )
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def convert_one(input_path: Path, args, severities: set = None,
                old_data: dict = None) -> int:
    """Run the full conversion pipeline for a single input file. Returns 0 or 1."""
    _info(f"[INFO] Parsing: {input_path}")

    # 1. Parse XML
    data = parse_ckl(input_path)

    # 2. Verify extraction
    if not data["vulnerabilities"]:
        _warn(
            "[WARNING] No <VULN> nodes were found in the checklist. "
            "Output files will be generated but will contain no vulnerability data."
        )

    if not data["asset"]:
        _warn("[WARNING] No <ASSET> node was found in the checklist.")

    # 3. Diff against the old scan — always on unfiltered data, so an active
    #    filter can never hide a remediated or newly-open finding.
    diff_content = build_diff(old_data, data) if old_data is not None else None

    # 4. Apply finding filters (affect every subsequent output)
    if args.open_only or severities:
        before = len(data["vulnerabilities"])
        data["vulnerabilities"] = filter_vulnerabilities(
            data["vulnerabilities"], args.open_only, severities)
        after = len(data["vulnerabilities"])
        active = []
        if args.open_only:
            active.append("open-only")
        if severities:
            active.append("severity=" + ",".join(sorted(severities)))
        _info(f"[INFO] Filters applied ({'; '.join(active)}): "
              f"{before} findings -> {after}")
        if before and not after:
            _warn("[WARNING] All findings were excluded by the active filters. "
                  "Output files will contain no vulnerability data.")

    # 5. Summary mode: print the report and write nothing.
    if args.summary:
        print(build_report(data))
        return 0

    # 6. Derive output paths
    stem = input_path.stem
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = input_path.parent

    json_path = output_dir / f"{stem}.json"
    toml_path = output_dir / f"{stem}.toml"
    md_path   = output_dir / f"{stem}.md"

    # 7. Serialise and write

    # --- JSON ----------------------------------------------------------------
    try:
        json_content = json.dumps(data, indent=2, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        print(f"[ERROR] Failed to serialise data to JSON: {exc}", file=sys.stderr)
        return 1

    ok_json = write_file(json_path, json_content, "JSON")

    # --- TOML ----------------------------------------------------------------
    toml_content = build_toml(data)
    ok_toml = write_file(toml_path, toml_content, "TOML")

    # --- Markdown ------------------------------------------------------------
    md_content = build_markdown(data)
    ok_md = write_file(md_path, md_content, "Markdown")

    outputs_ok = ok_json and ok_toml and ok_md

    # --- CSV (opt-in) ----------------------------------------------------------
    if args.csv:
        header, rows = build_csv_rows(data)
        ok_csv = write_csv(output_dir / f"{stem}.csv", header, rows)
        outputs_ok = outputs_ok and ok_csv

    # --- Report (opt-in) -----------------------------------------------------
    if args.report:
        report_path = output_dir / f"report_{stem}.txt"
        ok_report = write_file(report_path, build_report(data), "Report")
        outputs_ok = outputs_ok and ok_report

    # --- Prompt (opt-in) -----------------------------------------------------
    if args.prompt is not None:
        prompt_path = output_dir / f"prompt_{stem}.md"
        prompt_content = build_prompt_md(data, args.prompt, md_content)
        ok_prompt = write_file(prompt_path, prompt_content, f"Prompt ({args.prompt})")
        outputs_ok = outputs_ok and ok_prompt

    # --- Chunks (opt-in; value validated before parsing) ----------------------
    if args.chunk is not None:
        n      = args.chunk
        vulns  = data["vulnerabilities"]
        # Nothing to split → no chunk files (the no-VULN warning already fired).
        total  = (len(vulns) + n - 1) // n
        for i in range(total):
            chunk_data    = {**data, "vulnerabilities": vulns[i * n:(i + 1) * n]}
            chunk_content = f"<!-- Chunk {i + 1} of {total} -->\n\n" + build_markdown(chunk_data)
            chunk_path    = output_dir / f"{stem}_chunk_{i + 1:03d}.md"
            ok_c = write_file(chunk_path, chunk_content, f"Chunk {i + 1}/{total}")
            outputs_ok = outputs_ok and ok_c

    # --- Diff (opt-in) ---------------------------------------------------------
    if diff_content is not None:
        diff_path = output_dir / f"diff_{stem}.md"
        ok_diff = write_file(diff_path, diff_content, "Diff")
        outputs_ok = outputs_ok and ok_diff

    if outputs_ok:
        _info("[INFO] Conversion complete.")
        return 0

    print("[ERROR] One or more output files could not be written.", file=sys.stderr)
    return 1


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # Apply quiet flag before any output
    global _quiet
    _quiet = args.quiet

    # 1. Root guard (always first, per the documented security posture)
    check_root(args.run_as_root)

    # 2. Reject bad option values before any parsing or file writing
    if args.chunk is not None and args.chunk <= 0:
        print("[ERROR] --chunk value must be a positive integer.", file=sys.stderr)
        return 1

    severities = None
    if args.severity:
        severities = {s.strip().lower() for s in args.severity.split(",") if s.strip()}
        if not severities or severities - {"high", "medium", "low"}:
            print("[ERROR] --severity must be a comma-separated list of: "
                  "high, medium, low", file=sys.stderr)
            return 1

    if args.diff and len(args.input_file) > 1:
        print("[ERROR] --diff supports a single INPUT_FILE only.", file=sys.stderr)
        return 1

    if args.summary and (args.csv or args.report or args.prompt is not None
                         or args.chunk is not None or args.output_dir or args.diff):
        _warn("[WARNING] --summary writes no files; "
              "--csv/--report/--prompt/--chunk/--output-dir/--diff are ignored.")

    # 3. Parse the old checklist once for --diff (skipped in summary mode).
    old_data = None
    if args.diff and not args.summary:
        old_path = validate_input(args.diff)
        old_data = parse_ckl(old_path)

    # 4. Convert each input; keep going when one fails so a batch completes.
    failed = []
    for raw_path in args.input_file:
        try:
            input_path = validate_input(raw_path)
            rc = convert_one(input_path, args, severities, old_data)
        except SystemExit as exc:
            # validate_input()/parse_ckl() exit directly on a bad file; in a
            # batch we record the failure and continue with the next file.
            rc = exc.code if isinstance(exc.code, int) else 1
        if rc != 0:
            failed.append(raw_path)

    if failed:
        if len(args.input_file) > 1:
            print(f"[ERROR] {len(failed)} of {len(args.input_file)} file(s) failed: "
                  + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
