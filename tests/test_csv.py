"""Tests for build_csv_rows(), _field(), and the --csv flag in ckl_convert.py."""
import csv
import io
import json
import pytest

from tests.conftest import copy_fixture as _copy_fixture, run_main as _run_main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_data(asset=None, vulns=None):
    return {
        "source_file": "test.ckl",
        "converted_at": "2024-01-15T12:00:00Z",
        "asset": asset if asset is not None else {"HOST_NAME": "myhost", "HOST_IP": "1.2.3.4"},
        "vulnerabilities": vulns if vulns is not None else [],
    }


def _vuln(vuln_num="V-1", severity="high", status="Open", cci_ref=None,
          finding="", comments=""):
    stig = {"Vuln_Num": vuln_num, "Rule_ID": "SV-1_rule",
            "Rule_Title": "A rule", "Severity": severity}
    if cci_ref is not None:
        stig["CCI_REF"] = cci_ref
    return {
        "stig_data": stig,
        "STATUS": status,
        "FINDING_DETAILS": finding,
        "COMMENTS": comments,
        "SEVERITY_OVERRIDE": "",
        "SEVERITY_JUSTIFICATION": "",
    }


# ---------------------------------------------------------------------------
# _field
# ---------------------------------------------------------------------------

def test_field_string_passthrough(ckl_module):
    assert ckl_module._field("hello") == "hello"


def test_field_list_joined_with_semicolon(ckl_module):
    assert ckl_module._field(["CCI-1", "CCI-2"]) == "CCI-1; CCI-2"


def test_field_none_becomes_empty(ckl_module):
    assert ckl_module._field(None) == ""


# ---------------------------------------------------------------------------
# build_csv_rows
# ---------------------------------------------------------------------------

def test_csv_header_has_12_columns(ckl_module):
    header, _ = ckl_module.build_csv_rows(_make_data())
    assert len(header) == 12


def test_csv_rows_align_with_header(ckl_module):
    header, rows = ckl_module.build_csv_rows(_make_data(vulns=[_vuln()]))
    assert all(len(r) == len(header) for r in rows)


def test_csv_one_row_per_vuln(ckl_module):
    _, rows = ckl_module.build_csv_rows(_make_data(vulns=[_vuln("V-1"), _vuln("V-2")]))
    assert len(rows) == 2


def test_csv_empty_vulns_no_rows(ckl_module):
    _, rows = ckl_module.build_csv_rows(_make_data(vulns=[]))
    assert rows == []


def test_csv_asset_fields_repeated(ckl_module):
    _, rows = ckl_module.build_csv_rows(_make_data(vulns=[_vuln("V-1"), _vuln("V-2")]))
    assert all(r[0] == "myhost" and r[1] == "1.2.3.4" for r in rows)


def test_csv_host_falls_back_to_asset_name(ckl_module):
    data = _make_data(asset={"ASSET_NAME": "fallback"}, vulns=[_vuln()])
    _, rows = ckl_module.build_csv_rows(data)
    assert rows[0][0] == "fallback"


def test_csv_host_empty_when_no_names(ckl_module):
    data = _make_data(asset={}, vulns=[_vuln()])
    _, rows = ckl_module.build_csv_rows(data)
    assert rows[0][0] == ""


def test_csv_cci_ref_list_joined(ckl_module):
    data = _make_data(vulns=[_vuln(cci_ref=["CCI-000366", "CCI-001230"])])
    _, rows = ckl_module.build_csv_rows(data)
    assert rows[0][6] == "CCI-000366; CCI-001230"


# ---------------------------------------------------------------------------
# Integration: --csv flag
# ---------------------------------------------------------------------------

def _read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def test_integration_csv_flag_creates_csv(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    result = _run_main(ckl_module, f, ["--csv"])
    assert result == 0
    assert (tmp_path / "rhel8_stig.csv").exists()


def test_integration_csv_not_created_without_flag(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    assert not (tmp_path / "valid.csv").exists()


def test_integration_csv_row_count(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--csv"])
    rows = _read_csv(tmp_path / "rhel8_stig.csv")
    assert len(rows) == 16  # header + 15 findings


def test_integration_csv_embedded_commas_survive(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--csv"])
    rows = _read_csv(tmp_path / "rhel8_stig.csv")
    v230221 = next(r for r in rows if r[2] == "V-230221")
    # FINDING_DETAILS contains commas; csv.reader must give it back as one cell.
    assert "RHEL 8.3, which reached end of maintenance" in v230221[8]


def test_integration_csv_respects_filters(ckl_module, tmp_path):
    f = _copy_fixture("rhel8_stig.ckl", tmp_path)
    _run_main(ckl_module, f, ["--csv", "--open-only"])
    rows = _read_csv(tmp_path / "rhel8_stig.csv")
    assert len(rows) == 9  # header + 6 Open + 2 Not_Reviewed


def test_integration_csv_with_output_dir(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    out = tmp_path / "out"
    _run_main(ckl_module, f, ["--csv", "--output-dir", str(out)])
    assert (out / "valid.csv").exists()


def test_integration_csv_core_outputs_still_written(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--csv"])
    assert (tmp_path / "valid.json").exists()
    assert (tmp_path / "valid.toml").exists()
    assert (tmp_path / "valid.md").exists()


def test_integration_csv_suppressed_by_summary(ckl_module, tmp_path, capsys):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--csv", "--summary"])
    assert not (tmp_path / "valid.csv").exists()
    assert "--summary writes no files" in capsys.readouterr().err
