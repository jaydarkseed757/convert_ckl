"""Integration tests using the realistic RHEL 8 STIG checklist fixture (15 findings)."""
import json
import pathlib
import pytest
from unittest.mock import patch

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"

# Fixture stats (update these if the fixture file changes)
TOTAL_FINDINGS = 15
CAT_I_COUNT = 4    # high
CAT_II_COUNT = 7   # medium
CAT_III_COUNT = 4  # low
STATUS_OPEN = 6
STATUS_NAF = 4     # NotAFinding
STATUS_NA = 3      # Not Applicable
STATUS_NR = 2      # Not_Reviewed


def _copy_fixture(name: str, tmp_path: pathlib.Path) -> pathlib.Path:
    src = _FIXTURES / name
    dest = tmp_path / name
    dest.write_bytes(src.read_bytes())
    return dest


def _run_main(ckl_module, ckl_path: pathlib.Path, extra_argv: list = None):
    argv = ["ckl_convert", str(ckl_path)] + (extra_argv or [])
    with patch("sys.argv", argv), patch("os.geteuid", return_value=1000):
        return ckl_module.main()


# ---------------------------------------------------------------------------
# Pipeline: exit code and output files
# ---------------------------------------------------------------------------

def test_rhel8_main_returns_zero(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    assert _run_main(ckl_module, f) == 0


def test_rhel8_all_three_output_files_created(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    assert (tmp_path / "rhel8_stig.json").exists()
    assert (tmp_path / "rhel8_stig.toml").exists()
    assert (tmp_path / "rhel8_stig.md").exists()


# ---------------------------------------------------------------------------
# Asset fields
# ---------------------------------------------------------------------------

def test_rhel8_json_asset_host_name(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    assert data["asset"]["HOST_NAME"] == "rhel8-prod-01"


def test_rhel8_json_asset_ip(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    assert data["asset"]["HOST_IP"] == "10.0.1.100"


def test_rhel8_json_asset_fqdn(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    assert data["asset"]["HOST_FQDN"] == "rhel8-prod-01.corp.example.com"


def test_rhel8_json_asset_web_or_database(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    assert data["asset"]["WEB_OR_DATABASE"] == "No"


# ---------------------------------------------------------------------------
# Vulnerability counts
# ---------------------------------------------------------------------------

def test_rhel8_json_total_finding_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    assert len(data["vulnerabilities"]) == TOTAL_FINDINGS


def test_rhel8_json_cat_i_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    high = [v for v in data["vulnerabilities"] if v["stig_data"].get("Severity") == "high"]
    assert len(high) == CAT_I_COUNT


def test_rhel8_json_cat_ii_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    medium = [v for v in data["vulnerabilities"] if v["stig_data"].get("Severity") == "medium"]
    assert len(medium) == CAT_II_COUNT


def test_rhel8_json_cat_iii_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    low = [v for v in data["vulnerabilities"] if v["stig_data"].get("Severity") == "low"]
    assert len(low) == CAT_III_COUNT


def test_rhel8_json_status_open_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    opens = [v for v in data["vulnerabilities"] if v["STATUS"] == "Open"]
    assert len(opens) == STATUS_OPEN


def test_rhel8_json_status_notafinding_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    nafs = [v for v in data["vulnerabilities"] if v["STATUS"] == "NotAFinding"]
    assert len(nafs) == STATUS_NAF


def test_rhel8_json_status_not_applicable_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    nas = [v for v in data["vulnerabilities"] if v["STATUS"] == "Not Applicable"]
    assert len(nas) == STATUS_NA


def test_rhel8_json_status_not_reviewed_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    nrs = [v for v in data["vulnerabilities"] if v["STATUS"] == "Not_Reviewed"]
    assert len(nrs) == STATUS_NR


# ---------------------------------------------------------------------------
# Specific vuln field assertions
# ---------------------------------------------------------------------------

def _find_vuln(data, vuln_num):
    return next(v for v in data["vulnerabilities"] if v["stig_data"].get("Vuln_Num") == vuln_num)


def test_rhel8_v230221_multiple_cci_ref_is_list(ckl_module, tmp_path):
    """Repeated CCI_REF entries must be collected into a JSON array."""
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    v = _find_vuln(data, "V-230221")
    assert isinstance(v["stig_data"]["CCI_REF"], list)
    assert "CCI-000366" in v["stig_data"]["CCI_REF"]
    assert "CCI-001230" in v["stig_data"]["CCI_REF"]


def test_rhel8_v230223_severity_override_captured(ckl_module, tmp_path):
    """Severity override (high→medium) must be preserved in the output."""
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    v = _find_vuln(data, "V-230223")
    assert v["stig_data"]["Severity"] == "high"
    assert v["SEVERITY_OVERRIDE"] == "medium"
    assert "POA" in v["SEVERITY_JUSTIFICATION"]


def test_rhel8_v230232_full_stig_fields(ckl_module, tmp_path):
    """V-230232 has all major STIG fields populated; verify each is captured."""
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    v = _find_vuln(data, "V-230232")
    sd = v["stig_data"]
    assert sd["Rule_Ver"] == "RHEL-08-010110"
    assert "FIPS" in sd["Rule_Title"]
    assert "cryptographic" in sd["Vuln_Discuss"].lower()
    assert "fips-mode-setup" in sd["Check_Content"]
    assert "fips-mode-setup" in sd["Fix_Text"]
    assert "Version 1, Release 13" in sd["STIGRef"]
    assert sd["TargetKey"] == "4085"
    assert sd["STIG_UUID"] == "a24c57c6-3c08-4a36-9d14-6c6fb22d77bc"


def test_rhel8_v230232_status_and_finding(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    v = _find_vuln(data, "V-230232")
    assert v["STATUS"] == "NotAFinding"
    assert "FIPS mode is enabled" in v["FINDING_DETAILS"]


def test_rhel8_v230264_not_reviewed_empty_finding(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    v = _find_vuln(data, "V-230264")
    assert v["STATUS"] == "Not_Reviewed"
    assert v["FINDING_DETAILS"] == ""


def test_rhel8_v230283_not_applicable(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    v = _find_vuln(data, "V-230283")
    assert v["STATUS"] == "Not Applicable"
    assert "container" in v["COMMENTS"].lower()


def test_rhel8_v230244_two_cci_refs(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    v = _find_vuln(data, "V-230244")
    cci = v["stig_data"]["CCI_REF"]
    assert isinstance(cci, list)
    assert len(cci) == 2
    assert "CCI-000048" in cci
    assert "CCI-000050" in cci


# ---------------------------------------------------------------------------
# TOML output
# ---------------------------------------------------------------------------

def test_rhel8_toml_vuln_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "rhel8_stig.toml").read_text(encoding="utf-8")
    assert content.count("[[vulnerabilities]]") == TOTAL_FINDINGS


def test_rhel8_toml_asset_host_name(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "rhel8_stig.toml").read_text(encoding="utf-8")
    assert 'HOST_NAME = "rhel8-prod-01"' in content


def test_rhel8_toml_cci_ref_array(ckl_module, tmp_path):
    """Repeated CCI_REF must render as a TOML array."""
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "rhel8_stig.toml").read_text(encoding="utf-8")
    assert 'CCI_REF = ["CCI-000366", "CCI-001230"]' in content


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def test_rhel8_markdown_has_hostname_in_title(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "rhel8_stig.md").read_text(encoding="utf-8")
    assert "rhel8-prod-01" in content


def test_rhel8_markdown_has_all_statuses(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "rhel8_stig.md").read_text(encoding="utf-8")
    for status in ("Open", "NotAFinding", "Not Applicable", "Not_Reviewed"):
        assert status in content, f"Expected '{status}' in markdown output"


def test_rhel8_markdown_vuln_num_present(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "rhel8_stig.md").read_text(encoding="utf-8")
    assert "V-230221" in content
    assert "V-230232" in content
    assert "V-230340" in content


# ---------------------------------------------------------------------------
# --report flag
# ---------------------------------------------------------------------------

def test_rhel8_report_file_created(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    result = _run_main(ckl_module, f, ["--report"])
    assert result == 0
    assert (tmp_path / "report_rhel8_stig.txt").exists()


def test_rhel8_report_total_findings(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_rhel8_stig.txt").read_text(encoding="utf-8")
    assert f"Total findings : {TOTAL_FINDINGS}" in content


def test_rhel8_report_host_name(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_rhel8_stig.txt").read_text(encoding="utf-8")
    assert "rhel8-prod-01" in content


def test_rhel8_report_stig_ref_in_source(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_rhel8_stig.txt").read_text(encoding="utf-8")
    assert "rhel8_stig.ckl" in content


def test_rhel8_report_cat_labels_present(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_rhel8_stig.txt").read_text(encoding="utf-8")
    assert "CAT I (high)" in content
    assert "CAT II (medium)" in content
    assert "CAT III (low)" in content


def test_rhel8_report_cat_i_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_rhel8_stig.txt").read_text(encoding="utf-8")
    lines = content.splitlines()
    cat1_line = next(l for l in lines if l.startswith("CAT I (high)"))
    assert str(CAT_I_COUNT) in cat1_line


def test_rhel8_report_open_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_rhel8_stig.txt").read_text(encoding="utf-8")
    lines = content.splitlines()
    open_line = next(l for l in lines if l.startswith("Open"))
    assert str(STATUS_OPEN) in open_line


def test_rhel8_report_percentages_sum_to_100(ckl_module, tmp_path):
    """Status percentages extracted from the report must sum to 100.0."""
    import re
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_rhel8_stig.txt").read_text(encoding="utf-8")
    pcts = [float(m) for m in re.findall(r"\((\d+\.\d+)%\)", content)]
    # Select only the status section percentages (one per status, total = 4)
    status_pcts = pcts[:4]
    assert abs(sum(status_pcts) - 100.0) < 0.1
