#!/usr/bin/env python3
"""
ckl2csv.py — DISA STIG Checklist (.ckl / .chk) to CSV converter

Fully standalone: no imports beyond the Python standard library, and no
dependency on any other file in this project. Copy this single script onto
a target host to use it.

Requirements:
  - Python 3.6+
  - Zero external dependencies (stdlib only)
  - Must NOT be run as root (unless --run-as-root is passed)

Usage:
  python3 ckl2csv.py <input_file.ckl> [-o OUTPUT] [--run-as-root] [--quiet]
"""

import argparse
import csv
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_EXTENSIONS = {".ckl", ".chk"}

CSV_HEADER = [
    "Host_Name", "Host_IP",
    "Vuln_Num", "Severity", "Rule_ID", "Rule_Title", "CCI_REF",
    "Status", "Finding_Details", "Comments",
    "Severity_Override", "Severity_Justification",
]


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
    Validate the input file path. Returns a resolved Path on success;
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
    Extract every <VULN> node. For each vuln, collect:
      - All <STIG_DATA> key/value pairs  (Vuln_Attribute → Attribute_Data)
      - STATUS, FINDING_DETAILS, COMMENTS, SEVERITY_OVERRIDE, SEVERITY_JUSTIFICATION
    """
    vulns = []

    for vuln_node in root.findall(".//VULN"):
        entry: dict = {}

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

        for tag in ("STATUS", "FINDING_DETAILS", "COMMENTS",
                    "SEVERITY_OVERRIDE", "SEVERITY_JUSTIFICATION"):
            entry[tag] = (vuln_node.findtext(tag) or "").strip()

        vulns.append(entry)

    return vulns


def parse_ckl(filepath: Path) -> dict:
    """
    Parse the CKL/CHK XML file. Returns a dict with keys:
      'asset'           -> dict of asset metadata
      'vulnerabilities' -> list of vuln dicts
      'source_file'     -> str filename
    """
    try:
        tree = ET.parse(str(filepath))
    except ET.ParseError as exc:
        print(f"[ERROR] XML parse error in '{filepath}': {exc}", file=sys.stderr)
        sys.exit(1)

    root = tree.getroot()
    return {
        "source_file":     filepath.name,
        "asset":           parse_asset(root),
        "vulnerabilities": parse_vulnerabilities(root),
    }


# ---------------------------------------------------------------------------
# CSV generation
# ---------------------------------------------------------------------------

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
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ckl2csv.py",
        description=(
            "Convert a DISA STIG Checklist (.ckl/.chk) to a flat CSV file, "
            "one row per finding.\nStdlib-only — zero external dependencies. "
            "Fully standalone."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input_file",
        metavar="INPUT_FILE",
        help="Path to the STIG Checklist file (.ckl or .chk).",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        metavar="PATH",
        default=None,
        help="Output CSV path. Defaults to <input_stem>.csv next to the input file.",
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
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress [INFO] and [WARNING] messages. [ERROR] messages are always shown.",
    )
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    global _quiet
    _quiet = args.quiet

    # 1. Root guard
    check_root(args.run_as_root)

    # 2. Validate input
    input_path = validate_input(args.input_file)

    _info(f"[INFO] Parsing: {input_path}")

    # 3. Parse XML
    data = parse_ckl(input_path)

    # 4. Verify extraction
    if not data["vulnerabilities"]:
        _warn(
            "[WARNING] No <VULN> nodes were found in the checklist. "
            "The CSV will be written with a header row only."
        )

    if not data["asset"]:
        _warn("[WARNING] No <ASSET> node was found in the checklist.")

    # 5. Derive output path
    output_path = Path(args.output) if args.output else input_path.with_suffix(".csv")

    # 6. Build and write CSV
    header, rows = build_csv_rows(data)
    if write_csv(output_path, header, rows):
        _info("[INFO] Conversion complete.")
        return 0

    print("[ERROR] CSV file could not be written.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
