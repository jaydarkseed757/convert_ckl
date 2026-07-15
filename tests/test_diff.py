"""Tests for build_diff() and the --diff flag."""
import pytest

from tests.conftest import copy_fixture as _copy_fixture, run_main as _run_main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vuln(vuln_num="V-1", status="Open", severity="high", title="A rule"):
    return {
        "stig_data": {"Vuln_Num": vuln_num, "Rule_ID": f"SV-{vuln_num}_rule",
                      "Severity": severity, "Rule_Title": title},
        "STATUS": status,
        "FINDING_DETAILS": "",
        "COMMENTS": "",
        "SEVERITY_OVERRIDE": "",
        "SEVERITY_JUSTIFICATION": "",
    }


def _data(vulns, source="scan.ckl"):
    return {
        "source_file": source,
        "converted_at": "2024-01-15T12:00:00Z",
        "asset": {"HOST_NAME": "box"},
        "vulnerabilities": vulns,
    }


def _diff(ckl_module, old_vulns, new_vulns):
    return ckl_module.build_diff(_data(old_vulns, "old.ckl"), _data(new_vulns, "new.ckl"))


# ---------------------------------------------------------------------------
# build_diff — unit tests
# ---------------------------------------------------------------------------

def test_diff_no_changes(ckl_module):
    v = [_vuln("V-1", "Open")]
    out = _diff(ckl_module, v, v)
    assert "0 newly open, 0 remediated, 0 status changed, 0 added, 0 removed, 1 unchanged" in out


def test_diff_newly_open(ckl_module):
    out = _diff(ckl_module, [_vuln("V-1", "NotAFinding")], [_vuln("V-1", "Open")])
    assert "1 newly open" in out
    lines = out.splitlines()
    section = lines[lines.index("## Newly Open (1)"):]
    assert any("V-1" in l for l in section[:6])


def test_diff_remediated(ckl_module):
    out = _diff(ckl_module, [_vuln("V-1", "Open")], [_vuln("V-1", "NotAFinding")])
    assert "1 remediated" in out


def test_diff_not_reviewed_to_open_is_status_changed(ckl_module):
    # Both statuses are "open-ish", so this is a change, not newly open/remediated.
    out = _diff(ckl_module, [_vuln("V-1", "Not_Reviewed")], [_vuln("V-1", "Open")])
    assert "1 status changed" in out
    assert "0 newly open" in out


def test_diff_closed_to_closed_is_status_changed(ckl_module):
    out = _diff(ckl_module, [_vuln("V-1", "NotAFinding")], [_vuln("V-1", "Not Applicable")])
    assert "1 status changed" in out


def test_diff_added_open_finding_is_newly_open(ckl_module):
    out = _diff(ckl_module, [], [_vuln("V-2", "Open")])
    assert "1 newly open" in out
    assert "(not in old file)" in out


def test_diff_added_closed_finding_is_added(ckl_module):
    out = _diff(ckl_module, [], [_vuln("V-2", "NotAFinding")])
    assert "1 added" in out
    assert "0 newly open" in out


def test_diff_removed_finding(ckl_module):
    out = _diff(ckl_module, [_vuln("V-3", "Open")], [])
    assert "1 removed" in out
    assert "(not in new file)" in out


def test_diff_header_names_both_files(ckl_module):
    out = _diff(ckl_module, [_vuln()], [_vuln()])
    assert "old.ckl" in out
    assert "new.ckl" in out


def test_diff_empty_sections_show_none(ckl_module):
    out = _diff(ckl_module, [_vuln("V-1", "Open")], [_vuln("V-1", "Open")])
    assert "_None._" in out


def test_diff_matches_by_rule_id_when_vuln_num_missing(ckl_module):
    old = _vuln("", "Open")
    new = _vuln("", "NotAFinding")
    # Same Rule_ID (SV-_rule), no Vuln_Num → still matched → remediated.
    out = _diff(ckl_module, [old], [new])
    assert "1 remediated" in out


# ---------------------------------------------------------------------------
# Integration: --diff flag
# ---------------------------------------------------------------------------

def test_integration_diff_writes_diff_file(ckl_module, tmp_path):
    old = _copy_fixture("rhel8_stig.ckl", tmp_path)
    new_text = old.read_text(encoding="utf-8").replace(
        "<STATUS>Open</STATUS>", "<STATUS>NotAFinding</STATUS>")
    new = tmp_path / "newscan.ckl"
    new.write_text(new_text, encoding="utf-8")

    result = _run_main(ckl_module, new, ["--diff", str(old)])
    assert result == 0
    content = (tmp_path / "diff_newscan.md").read_text(encoding="utf-8")
    # rhel8_stig.ckl has 6 Open findings; all were flipped to NotAFinding.
    assert "6 remediated" in content


def test_integration_diff_not_written_without_flag(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    assert not (tmp_path / "diff_valid.md").exists()


def test_integration_diff_with_multiple_inputs_errors(ckl_module, tmp_path, capsys):
    f1 = _copy_fixture("valid.ckl", tmp_path)
    f2 = _copy_fixture("minimal.ckl", tmp_path)
    result = _run_main(ckl_module, f1, [str(f2), "--diff", str(f1)])
    assert result == 1
    assert "single INPUT_FILE" in capsys.readouterr().err


def test_integration_diff_ignores_active_filters(ckl_module, tmp_path):
    """The diff must reflect ALL findings even when --open-only is active."""
    old = _copy_fixture("rhel8_stig.ckl", tmp_path)
    new_text = old.read_text(encoding="utf-8").replace(
        "<STATUS>Open</STATUS>", "<STATUS>NotAFinding</STATUS>")
    new = tmp_path / "newscan.ckl"
    new.write_text(new_text, encoding="utf-8")

    _run_main(ckl_module, new, ["--diff", str(old), "--open-only"])
    content = (tmp_path / "diff_newscan.md").read_text(encoding="utf-8")
    # Remediated findings are closed in NEW, so --open-only would hide them
    # if the diff (incorrectly) used filtered data.
    assert "6 remediated" in content
