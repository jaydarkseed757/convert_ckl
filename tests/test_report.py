"""Tests for build_report() — plain-text processing summary."""
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_data(asset=None, vulns=None, source="test.ckl", converted="2024-01-15T12:00:00Z"):
    return {
        "source_file": source,
        "converted_at": converted,
        "asset": asset if asset is not None else {"HOST_NAME": "myhost"},
        "vulnerabilities": vulns if vulns is not None else [],
    }


def _vuln(severity="high", status="Open"):
    return {
        "stig_data": {"Vuln_Num": "V-1", "Rule_ID": "SV-1_rule", "Severity": severity},
        "STATUS": status,
        "FINDING_DETAILS": "",
        "COMMENTS": "",
        "SEVERITY_OVERRIDE": "",
        "SEVERITY_JUSTIFICATION": "",
    }


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def test_report_header_has_title(ckl_module):
    out = ckl_module.build_report(_make_data())
    assert "STIG Checklist Processing Report" in out


def test_report_header_source_file(ckl_module):
    out = ckl_module.build_report(_make_data(source="scan.ckl"))
    assert "Source file    : scan.ckl" in out


def test_report_header_generated_timestamp(ckl_module):
    out = ckl_module.build_report(_make_data(converted="2024-01-15T12:00:00Z"))
    assert "Generated      : 2024-01-15T12:00:00Z" in out


def test_report_header_uses_host_name(ckl_module):
    out = ckl_module.build_report(_make_data(asset={"HOST_NAME": "myhost"}))
    assert "Host           : myhost" in out


def test_report_header_falls_back_to_asset_name(ckl_module):
    out = ckl_module.build_report(_make_data(asset={"ASSET_NAME": "fallback-host"}))
    assert "Host           : fallback-host" in out


def test_report_header_falls_back_to_unknown_host(ckl_module):
    out = ckl_module.build_report(_make_data(asset={}))
    assert "Host           : Unknown Host" in out


def test_report_total_findings(ckl_module):
    vulns = [_vuln(), _vuln(), _vuln()]
    out = ckl_module.build_report(_make_data(vulns=vulns))
    assert "Total findings : 3" in out


def test_report_returns_str(ckl_module):
    assert isinstance(ckl_module.build_report(_make_data()), str)


# ---------------------------------------------------------------------------
# Status breakdown
# ---------------------------------------------------------------------------

def test_report_status_breakdown_section_header(ckl_module):
    out = ckl_module.build_report(_make_data(vulns=[_vuln()]))
    assert "Status Breakdown" in out


def test_report_status_counts(ckl_module):
    vulns = [
        _vuln(status="Open"),
        _vuln(status="Open"),
        _vuln(status="NotAFinding"),
    ]
    out = ckl_module.build_report(_make_data(vulns=vulns))
    lines = out.splitlines()
    open_line = next(l for l in lines if l.startswith("Open"))
    naf_line = next(l for l in lines if l.startswith("NotAFinding"))
    assert "2" in open_line
    assert "1" in naf_line


def test_report_status_percentages(ckl_module):
    vulns = [_vuln(status="Open"), _vuln(status="NotAFinding")]
    out = ckl_module.build_report(_make_data(vulns=vulns))
    # 1 of 2 == 50.0%
    assert "(50.0%)" in out


def test_report_status_sorted_by_count_desc(ckl_module):
    vulns = [
        _vuln(status="NotAFinding"),
        _vuln(status="Open"),
        _vuln(status="Open"),
    ]
    out = ckl_module.build_report(_make_data(vulns=vulns))
    lines = out.splitlines()
    open_idx = next(i for i, l in enumerate(lines) if l.startswith("Open"))
    naf_idx = next(i for i, l in enumerate(lines) if l.startswith("NotAFinding"))
    assert open_idx < naf_idx  # higher count listed first


def test_report_status_missing_status_becomes_unknown(ckl_module):
    v = _vuln()
    v["STATUS"] = ""
    out = ckl_module.build_report(_make_data(vulns=[v]))
    assert "Unknown" in out


# ---------------------------------------------------------------------------
# Severity breakdown
# ---------------------------------------------------------------------------

def test_report_severity_breakdown_section_header(ckl_module):
    out = ckl_module.build_report(_make_data(vulns=[_vuln()]))
    assert "Severity Breakdown" in out


def test_report_severity_maps_to_cat_labels(ckl_module):
    vulns = [_vuln(severity="high"), _vuln(severity="medium"), _vuln(severity="low")]
    out = ckl_module.build_report(_make_data(vulns=vulns))
    assert "CAT I (high)" in out
    assert "CAT II (medium)" in out
    assert "CAT III (low)" in out


def test_report_severity_counts(ckl_module):
    vulns = [_vuln(severity="high"), _vuln(severity="high"), _vuln(severity="low")]
    out = ckl_module.build_report(_make_data(vulns=vulns))
    lines = out.splitlines()
    cat1 = next(l for l in lines if l.startswith("CAT I (high)"))
    assert "2" in cat1


def test_report_severity_cat_order(ckl_module):
    vulns = [_vuln(severity="low"), _vuln(severity="high"), _vuln(severity="medium")]
    out = ckl_module.build_report(_make_data(vulns=vulns))
    lines = out.splitlines()
    i1 = next(i for i, l in enumerate(lines) if l.startswith("CAT I (high)"))
    i2 = next(i for i, l in enumerate(lines) if l.startswith("CAT II (medium)"))
    i3 = next(i for i, l in enumerate(lines) if l.startswith("CAT III (low)"))
    assert i1 < i2 < i3


def test_report_unknown_severity_grouped(ckl_module):
    out = ckl_module.build_report(_make_data(vulns=[_vuln(severity="critical")]))
    assert "Other (critical)" in out


def test_report_empty_severity_is_unspecified(ckl_module):
    out = ckl_module.build_report(_make_data(vulns=[_vuln(severity="")]))
    assert "Unspecified" in out


# ---------------------------------------------------------------------------
# Severity override
# ---------------------------------------------------------------------------

def test_report_severity_override_recategorises(ckl_module):
    v = _vuln(severity="high")
    v["SEVERITY_OVERRIDE"] = "medium"
    out = ckl_module.build_report(_make_data(vulns=[v]))
    assert "CAT II (medium)" in out
    assert "CAT I (high)" not in out


def test_report_severity_override_annotation(ckl_module):
    v = _vuln(severity="high")
    v["SEVERITY_OVERRIDE"] = "medium"
    out = ckl_module.build_report(_make_data(vulns=[v]))
    lines = out.splitlines()
    cat2 = next(l for l in lines if l.startswith("CAT II (medium)"))
    assert "[1 overridden]" in cat2


def test_report_no_override_no_annotation(ckl_module):
    out = ckl_module.build_report(_make_data(vulns=[_vuln(severity="medium")]))
    assert "overridden" not in out


# ---------------------------------------------------------------------------
# Empty vulnerability list
# ---------------------------------------------------------------------------

def test_report_no_vulns_total_zero(ckl_module):
    out = ckl_module.build_report(_make_data(vulns=[]))
    assert "Total findings : 0" in out


def test_report_no_vulns_shows_none_placeholder(ckl_module):
    out = ckl_module.build_report(_make_data(vulns=[]))
    assert "(none)" in out


def test_report_no_vulns_does_not_raise(ckl_module):
    # No ZeroDivisionError on percentage computation.
    ckl_module.build_report(_make_data(vulns=[]))


def test_report_override_equal_to_original_not_annotated(ckl_module):
    """Exporters that echo Severity into SEVERITY_OVERRIDE must not trigger [N overridden]."""
    v = _vuln(severity="high")
    v["SEVERITY_OVERRIDE"] = "high"
    out = ckl_module.build_report(_make_data(vulns=[v]))
    assert "overridden" not in out
    assert "CAT I (high)" in out
