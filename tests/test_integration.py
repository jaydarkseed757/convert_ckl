"""End-to-end integration tests for the full conversion pipeline (main())."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch


# A realistic .ckl fixture: two vulns, one with repeated CCI_REF.
_SAMPLE_CKL = """\
<CHECKLIST>
  <ASSET>
    <HOST_NAME>rhel8-node01</HOST_NAME>
    <HOST_IP>192.168.1.10</HOST_IP>
    <HOST_MAC>AA:BB:CC:DD:EE:FF</HOST_MAC>
    <HOST_FQDN>rhel8-node01.example.com</HOST_FQDN>
    <TECH_AREA>Operating System</TECH_AREA>
    <TARGET_KEY>4081</TARGET_KEY>
  </ASSET>
  <VULN>
    <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-230221</ATTRIBUTE_DATA></STIG_DATA>
    <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
    <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-230221r858734_rule</ATTRIBUTE_DATA></STIG_DATA>
    <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000366</ATTRIBUTE_DATA></STIG_DATA>
    <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-001199</ATTRIBUTE_DATA></STIG_DATA>
    <STATUS>NotAFinding</STATUS>
    <FINDING_DETAILS>Verified compliant.</FINDING_DETAILS>
    <COMMENTS>Checked on 2024-01-15.</COMMENTS>
    <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
    <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
  </VULN>
  <VULN>
    <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-230222</ATTRIBUTE_DATA></STIG_DATA>
    <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
    <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-230222r858735_rule</ATTRIBUTE_DATA></STIG_DATA>
    <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000054</ATTRIBUTE_DATA></STIG_DATA>
    <STATUS>Open</STATUS>
    <FINDING_DETAILS>Patching required.</FINDING_DETAILS>
    <COMMENTS></COMMENTS>
    <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
    <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
  </VULN>
</CHECKLIST>
"""


def _run_main(ckl_module, ckl_path: Path, extra_argv: list = None):
    """Invoke main() with sys.argv pointing at ckl_path, running as non-root."""
    argv = ["ckl_convert", str(ckl_path)] + (extra_argv or [])
    with patch("sys.argv", argv), patch("os.geteuid", return_value=1000):
        return ckl_module.main()


# ---------------------------------------------------------------------------
# Happy path: full pipeline with a realistic fixture
# ---------------------------------------------------------------------------

def test_integration_main_returns_zero(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    assert _run_main(ckl_module, f) == 0


def test_integration_all_three_output_files_created(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    assert (tmp_path / "checklist.json").exists()
    assert (tmp_path / "checklist.toml").exists()
    assert (tmp_path / "checklist.md").exists()


def test_integration_output_files_in_same_dir_as_input(ckl_module, tmp_path):
    subdir = tmp_path / "scans"
    subdir.mkdir()
    f = subdir / "host.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    assert (subdir / "host.json").exists()
    assert (subdir / "host.toml").exists()
    assert (subdir / "host.md").exists()


# ---------------------------------------------------------------------------
# JSON output correctness
# ---------------------------------------------------------------------------

def test_integration_json_is_valid_and_has_expected_keys(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "checklist.json").read_text(encoding="utf-8"))
    assert set(data.keys()) == {"source_file", "converted_at", "asset", "vulnerabilities"}


def test_integration_json_asset_fields(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "checklist.json").read_text(encoding="utf-8"))
    assert data["asset"]["HOST_NAME"] == "rhel8-node01"
    assert data["asset"]["HOST_IP"] == "192.168.1.10"


def test_integration_json_vulnerabilities(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "checklist.json").read_text(encoding="utf-8"))
    assert len(data["vulnerabilities"]) == 2
    v0 = data["vulnerabilities"][0]
    assert v0["STATUS"] == "NotAFinding"
    assert v0["stig_data"]["Vuln_Num"] == "V-230221"
    # Repeated CCI_REF must survive as a list through the full pipeline
    assert v0["stig_data"]["CCI_REF"] == ["CCI-000366", "CCI-001199"]


# ---------------------------------------------------------------------------
# TOML output correctness
# ---------------------------------------------------------------------------

def test_integration_toml_has_asset_table(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    content = (tmp_path / "checklist.toml").read_text(encoding="utf-8")
    assert "[asset]" in content
    assert "HOST_NAME" in content


def test_integration_toml_has_vulnerabilities_array(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    content = (tmp_path / "checklist.toml").read_text(encoding="utf-8")
    assert "[[vulnerabilities]]" in content


def test_integration_toml_vuln_count_matches(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    content = (tmp_path / "checklist.toml").read_text(encoding="utf-8")
    assert content.count("[[vulnerabilities]]") == 2


# ---------------------------------------------------------------------------
# Markdown output correctness
# ---------------------------------------------------------------------------

def test_integration_markdown_has_title(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    content = (tmp_path / "checklist.md").read_text(encoding="utf-8")
    assert content.startswith("#")
    assert "rhel8-node01" in content


def test_integration_markdown_has_expected_sections(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    content = (tmp_path / "checklist.md").read_text(encoding="utf-8")
    assert "## Asset Information" in content
    assert "## Vulnerability Summary" in content
    assert "## Detailed Findings" in content


def test_integration_markdown_status_counts(ckl_module, tmp_path):
    f = tmp_path / "checklist.ckl"
    f.write_text(_SAMPLE_CKL, encoding="utf-8")
    _run_main(ckl_module, f)
    content = (tmp_path / "checklist.md").read_text(encoding="utf-8")
    # 1 NotAFinding, 1 Open in the fixture
    assert "NotAFinding" in content
    assert "Open" in content


# ---------------------------------------------------------------------------
# Warning paths: empty vuln list and missing asset
# ---------------------------------------------------------------------------

def test_integration_warns_on_empty_vuln_list(ckl_module, tmp_path, capsys):
    no_vulns = "<CHECKLIST><ASSET><HOST_NAME>box</HOST_NAME></ASSET></CHECKLIST>"
    f = tmp_path / "empty_vulns.ckl"
    f.write_text(no_vulns, encoding="utf-8")
    _run_main(ckl_module, f)
    assert "[WARNING]" in capsys.readouterr().err


def test_integration_warns_on_missing_asset(ckl_module, tmp_path, capsys):
    no_asset = (
        "<CHECKLIST><VULN>"
        "<STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS>Open</STATUS><FINDING_DETAILS></FINDING_DETAILS>"
        "<COMMENTS></COMMENTS><SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>"
        "<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>"
        "</VULN></CHECKLIST>"
    )
    f = tmp_path / "no_asset.ckl"
    f.write_text(no_asset, encoding="utf-8")
    _run_main(ckl_module, f)
    assert "[WARNING]" in capsys.readouterr().err
