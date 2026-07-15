"""Tests for filter_vulnerabilities() and the --open-only / --severity flags."""
import json
import pytest

from tests.conftest import copy_fixture as _copy_fixture, run_main as _run_main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vuln(severity="high", status="Open", override=""):
    return {
        "stig_data": {"Vuln_Num": "V-1", "Rule_ID": "SV-1_rule", "Severity": severity},
        "STATUS": status,
        "FINDING_DETAILS": "",
        "COMMENTS": "",
        "SEVERITY_OVERRIDE": override,
        "SEVERITY_JUSTIFICATION": "",
    }


# ---------------------------------------------------------------------------
# filter_vulnerabilities — unit tests
# ---------------------------------------------------------------------------

def test_filter_no_filters_returns_all(ckl_module):
    vulns = [_vuln(), _vuln(status="NotAFinding")]
    assert ckl_module.filter_vulnerabilities(vulns) == vulns


def test_filter_open_only_keeps_open_and_not_reviewed(ckl_module):
    vulns = [
        _vuln(status="Open"),
        _vuln(status="Not_Reviewed"),
        _vuln(status="NotAFinding"),
        _vuln(status="Not Applicable"),
    ]
    out = ckl_module.filter_vulnerabilities(vulns, open_only=True)
    assert [v["STATUS"] for v in out] == ["Open", "Not_Reviewed"]


def test_filter_severity_single_level(ckl_module):
    vulns = [_vuln(severity="high"), _vuln(severity="medium"), _vuln(severity="low")]
    out = ckl_module.filter_vulnerabilities(vulns, severities={"high"})
    assert len(out) == 1
    assert out[0]["stig_data"]["Severity"] == "high"


def test_filter_severity_multiple_levels(ckl_module):
    vulns = [_vuln(severity="high"), _vuln(severity="medium"), _vuln(severity="low")]
    out = ckl_module.filter_vulnerabilities(vulns, severities={"high", "low"})
    assert len(out) == 2


def test_filter_severity_uses_override(ckl_module):
    """A high finding overridden to medium must NOT match --severity high."""
    vulns = [_vuln(severity="high", override="medium")]
    assert ckl_module.filter_vulnerabilities(vulns, severities={"high"}) == []
    assert len(ckl_module.filter_vulnerabilities(vulns, severities={"medium"})) == 1


def test_filter_combined(ckl_module):
    vulns = [
        _vuln(severity="high", status="Open"),
        _vuln(severity="high", status="NotAFinding"),
        _vuln(severity="low", status="Open"),
    ]
    out = ckl_module.filter_vulnerabilities(vulns, open_only=True, severities={"high"})
    assert len(out) == 1
    assert out[0]["STATUS"] == "Open"
    assert out[0]["stig_data"]["Severity"] == "high"


def test_filter_can_empty_the_list(ckl_module):
    vulns = [_vuln(severity="low", status="NotAFinding")]
    assert ckl_module.filter_vulnerabilities(vulns, open_only=True) == []


def test_filter_does_not_mutate_input(ckl_module):
    vulns = [_vuln(status="NotAFinding")]
    ckl_module.filter_vulnerabilities(vulns, open_only=True)
    assert len(vulns) == 1


# ---------------------------------------------------------------------------
# Integration: flags affect the output files
# ---------------------------------------------------------------------------

def test_integration_open_only_filters_json(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    result = _run_main(ckl_module, f, ["--open-only"])
    assert result == 0
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    # rhel8_stig.ckl: 6 Open + 2 Not_Reviewed
    assert len(data["vulnerabilities"]) == 8
    assert all(v["STATUS"] in ("Open", "Not_Reviewed") for v in data["vulnerabilities"])


def test_integration_severity_filter_json(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--severity", "high"])
    data = json.loads((tmp_path / "rhel8_stig.json").read_text(encoding="utf-8"))
    # 4 raw high, minus V-230223 (overridden to medium) = 3
    assert len(data["vulnerabilities"]) == 3


def test_integration_filter_provenance_line(ckl_module, tmp_path, capsys):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--open-only"])
    assert "Filters applied" in capsys.readouterr().out


def test_integration_invalid_severity_exits_one(ckl_module, tmp_path, capsys):
    f = _copy_fixture("valid.ckl", tmp_path)
    result = _run_main(ckl_module, f, ["--severity", "critical"])
    assert result == 1
    assert "[ERROR]" in capsys.readouterr().err
    assert not (tmp_path / "valid.json").exists()


def test_integration_filters_affect_report(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--open-only", "--report"])
    content = (tmp_path / "report_rhel8_stig.txt").read_text(encoding="utf-8")
    assert "Total findings : 8" in content


def test_integration_filter_to_empty_warns(ckl_module, tmp_path, capsys):
    f = _copy_fixture("minimal.ckl", tmp_path)
    # minimal.ckl has one Open vuln with no Severity → severity filter empties it
    result = _run_main(ckl_module, f, ["--severity", "high"])
    assert result == 0
    assert "excluded by the active filters" in capsys.readouterr().err
