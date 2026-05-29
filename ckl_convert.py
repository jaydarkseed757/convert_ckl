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
# Root guard
# ---------------------------------------------------------------------------

def check_root(allow_root: bool) -> None:
    """Block execution as root unless explicitly overridden."""
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

    if not os.access(p, os.R_OK):
        print(f"[ERROR] No read permission on file: {path}", file=sys.stderr)
        sys.exit(1)

    if p.stat().st_size == 0:
        print(f"[ERROR] File is empty: {path}", file=sys.stderr)
        sys.exit(1)

    if p.suffix.lower() not in VALID_EXTENSIONS:
        print(
            f"[WARNING] Unexpected file extension '{p.suffix}'. "
            f"Expected one of {sorted(VALID_EXTENSIONS)}. Attempting to parse anyway.",
            file=sys.stderr,
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
    except ET.ParseError as exc:
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


def _toml_kv(key: str, value) -> str:
    """
    Return a single TOML `key = value` line.

    A string value is emitted as a quoted basic string; a list value is
    emitted as a TOML array of quoted strings (this is how repeated
    STIG_DATA attributes such as CCI_REF are represented).
    """
    if isinstance(value, list):
        items = ", ".join(f'"{_toml_escape_string(str(v))}"' for v in value)
        return f"{key} = [{items}]"
    return f'{key} = "{_toml_escape_string(str(value))}"'


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


def build_markdown(data: dict) -> str:
    """
    Build a Markdown document with:
      - A title block
      - Asset metadata as a definition list
      - A summary table of vulnerabilities
    """
    lines: list = []

    asset = data["asset"]
    host  = asset.get("HOST_NAME") or asset.get("ASSET_NAME") or "Unknown Host"

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
        # Count by status
        status_counts: dict = {}
        for v in vulns:
            s = v.get("STATUS", "Unknown")
            status_counts[s] = status_counts.get(s, 0) + 1

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

        finding = vuln.get("FINDING_DETAILS", "").strip()
        if finding:
            lines.append("")
            lines.append("**Finding Details:**")
            lines.append("")
            lines.append(finding)

        comments = vuln.get("COMMENTS", "").strip()
        if comments:
            lines.append("")
            lines.append("**Comments:**")
            lines.append("")
            lines.append(comments)

        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# File writing helpers
# ---------------------------------------------------------------------------

def write_file(path: Path, content: str, label: str) -> bool:
    """Write content to path with error handling. Returns True on success."""
    try:
        path.write_text(content, encoding="utf-8")
        print(f"[OK] {label} written → {path}")
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
        help="Path to the STIG Checklist file (.ckl or .chk).",
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
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # 1. Root guard
    check_root(args.run_as_root)

    # 2. Validate input
    input_path = validate_input(args.input_file)

    print(f"[INFO] Parsing: {input_path}")

    # 3. Parse XML
    data = parse_ckl(input_path)

    # 4. Verify extraction
    if not data["vulnerabilities"]:
        print(
            "[WARNING] No <VULN> nodes were found in the checklist. "
            "Output files will be generated but will contain no vulnerability data.",
            file=sys.stderr,
        )

    if not data["asset"]:
        print(
            "[WARNING] No <ASSET> node was found in the checklist.",
            file=sys.stderr,
        )

    # 5. Derive output paths (same directory as input, same stem)
    stem       = input_path.stem
    output_dir = input_path.parent

    json_path = output_dir / f"{stem}.json"
    toml_path = output_dir / f"{stem}.toml"
    md_path   = output_dir / f"{stem}.md"

    # 6. Serialise and write

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

    if ok_json and ok_toml and ok_md:
        print("[INFO] Conversion complete.")
        return 0

    print("[ERROR] One or more output files could not be written.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
