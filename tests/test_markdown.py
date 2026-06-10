"""Tests for _md_escape() and build_markdown()."""
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


def _vuln(vuln_num="V-1", rule_id="SV-1_rule", severity="high", status="Open",
          finding="", comments="", title="", cci_ref=None):
    stig = {"Vuln_Num": vuln_num, "Rule_ID": rule_id, "Severity": severity}
    if title:
        stig["Rule_Title"] = title
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
# _md_escape
# ---------------------------------------------------------------------------

def test_md_escape_string_passthrough(ckl_module):
    assert ckl_module._md_escape("hello") == "hello"


def test_md_escape_pipe_escaped(ckl_module):
    assert ckl_module._md_escape("a|b") == r"a\|b"


def test_md_escape_newline_becomes_space(ckl_module):
    assert ckl_module._md_escape("a\nb") == "a b"


def test_md_escape_carriage_return_becomes_space(ckl_module):
    assert ckl_module._md_escape("a\rb") == "a b"


def test_md_escape_list_joined_with_comma(ckl_module):
    assert ckl_module._md_escape(["CCI-001", "CCI-002"]) == "CCI-001, CCI-002"


def test_md_escape_list_with_pipe_escaped(ckl_module):
    assert ckl_module._md_escape(["a|b", "c"]) == r"a\|b, c"


def test_md_escape_non_string_converted(ckl_module):
    assert ckl_module._md_escape(42) == "42"


def test_md_escape_empty_string(ckl_module):
    assert ckl_module._md_escape("") == ""


def test_md_escape_empty_list(ckl_module):
    assert ckl_module._md_escape([]) == ""


# ---------------------------------------------------------------------------
# build_markdown — title / host name fallback
# ---------------------------------------------------------------------------

def test_build_markdown_uses_host_name(ckl_module):
    out = ckl_module.build_markdown(_make_data(asset={"HOST_NAME": "myhost"}))
    assert "myhost" in out.splitlines()[0]


def test_build_markdown_falls_back_to_asset_name(ckl_module):
    out = ckl_module.build_markdown(_make_data(asset={"ASSET_NAME": "fallback-host"}))
    assert "fallback-host" in out.splitlines()[0]


def test_build_markdown_falls_back_to_unknown_host(ckl_module):
    out = ckl_module.build_markdown(_make_data(asset={}))
    assert "Unknown Host" in out.splitlines()[0]


def test_build_markdown_title_starts_with_h1(ckl_module):
    out = ckl_module.build_markdown(_make_data())
    assert out.startswith("# ")


# ---------------------------------------------------------------------------
# build_markdown — asset section
# ---------------------------------------------------------------------------

def test_build_markdown_asset_section_header(ckl_module):
    out = ckl_module.build_markdown(_make_data())
    assert "## Asset Information" in out


def test_build_markdown_asset_fields_rendered(ckl_module):
    out = ckl_module.build_markdown(_make_data(asset={"HOST_NAME": "box", "HOST_IP": "1.2.3.4"}))
    assert "HOST_NAME" in out
    assert "box" in out
    assert "HOST_IP" in out
    assert "1.2.3.4" in out


def test_build_markdown_empty_asset_value_shows_not_set(ckl_module):
    out = ckl_module.build_markdown(_make_data(asset={"HOST_NAME": "box", "HOST_IP": ""}))
    assert "_not set_" in out


def test_build_markdown_no_asset_data_shows_placeholder(ckl_module):
    out = ckl_module.build_markdown(_make_data(asset={}))
    assert "_No asset data found._" in out


# ---------------------------------------------------------------------------
# build_markdown — vulnerability summary section
# ---------------------------------------------------------------------------

def test_build_markdown_vuln_summary_header(ckl_module):
    out = ckl_module.build_markdown(_make_data())
    assert "## Vulnerability Summary" in out


def test_build_markdown_no_vulns_shows_placeholder(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[]))
    assert "_No vulnerabilities found._" in out


def test_build_markdown_vuln_count_shown(ckl_module):
    vulns = [_vuln("V-1", status="Open"), _vuln("V-2", status="NotAFinding")]
    out = ckl_module.build_markdown(_make_data(vulns=vulns))
    assert "2" in out


def test_build_markdown_status_counts(ckl_module):
    vulns = [
        _vuln("V-1", status="Open"),
        _vuln("V-2", status="Open"),
        _vuln("V-3", status="NotAFinding"),
    ]
    out = ckl_module.build_markdown(_make_data(vulns=vulns))
    assert "Open" in out
    assert "NotAFinding" in out


def test_build_markdown_summary_table_headers(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln()]))
    assert "Vuln_Num" in out
    assert "Rule_ID" in out
    assert "Severity" in out
    assert "Status" in out


def test_build_markdown_summary_table_row_content(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln("V-99", "SV-99_rule", "medium", "Open")]))
    assert "V-99" in out
    assert "SV-99_rule" in out
    assert "medium" in out


# ---------------------------------------------------------------------------
# build_markdown — detailed findings section
# ---------------------------------------------------------------------------

def test_build_markdown_detailed_findings_header(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln()]))
    assert "## Detailed Findings" in out


def test_build_markdown_finding_heading_uses_vuln_and_rule(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln("V-42", "SV-42_rule")]))
    assert "V-42" in out
    assert "SV-42_rule" in out


def test_build_markdown_optional_title_rendered_when_present(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(title="Ensure SELinux is enabled")]))
    assert "Ensure SELinux is enabled" in out


def test_build_markdown_optional_title_absent_when_empty(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(title="")]))
    assert "**Title:**" not in out


def test_build_markdown_finding_details_rendered_when_present(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(finding="Patch missing.")]))
    assert "Finding Details" in out
    assert "Patch missing." in out


def test_build_markdown_finding_details_absent_when_empty(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(finding="")]))
    assert "Finding Details" not in out


def test_build_markdown_comments_rendered_when_present(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(comments="Reviewed OK.")]))
    assert "Comments" in out
    assert "Reviewed OK." in out


def test_build_markdown_comments_absent_when_empty(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(comments="")]))
    assert "**Comments:**" not in out


def test_build_markdown_list_severity_rendered_via_md_escape(ckl_module):
    # build_markdown passes stig_data values through _md_escape, which joins lists.
    # Verify a list-typed Severity doesn't crash and renders joined output.
    vuln = _vuln(severity="high")
    vuln["stig_data"]["Severity"] = ["high", "medium"]
    out = ckl_module.build_markdown(_make_data(vulns=[vuln]))
    assert "high" in out
    assert "medium" in out


# ---------------------------------------------------------------------------
# Free-text blocks rendered as blockquotes (Markdown-injection containment)
# ---------------------------------------------------------------------------

def test_build_markdown_finding_details_blockquoted(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(finding="Patch missing.")]))
    assert "> Patch missing." in out


def test_build_markdown_comments_blockquoted(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(comments="Reviewed OK.")]))
    assert "> Reviewed OK." in out


def test_build_markdown_finding_details_hr_neutralised(ckl_module):
    # A '---' line inside finding details must not render as a bare horizontal
    # rule that mimics the per-finding separator.
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(finding="before\n---\nafter")]))
    assert "> ---" in out
    lines = out.splitlines()
    # The only bare '---' lines are the structural separators, one per finding.
    assert lines.count("---") == 1


def test_build_markdown_multiline_finding_each_line_quoted(ckl_module):
    out = ckl_module.build_markdown(_make_data(vulns=[_vuln(finding="line one\nline two")]))
    assert "> line one" in out
    assert "> line two" in out
