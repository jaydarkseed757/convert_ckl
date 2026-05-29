"""Tests for _toml_escape_string(), _toml_kv(), and build_toml()."""
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
          finding="", comments="", cci_ref=None):
    stig = {"Vuln_Num": vuln_num, "Rule_ID": rule_id, "Severity": severity}
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
# _toml_escape_string
# ---------------------------------------------------------------------------

def test_toml_escape_empty_string(ckl_module):
    assert ckl_module._toml_escape_string("") == ""


def test_toml_escape_plain_string_unchanged(ckl_module):
    assert ckl_module._toml_escape_string("hello world") == "hello world"


def test_toml_escape_backslash(ckl_module):
    assert ckl_module._toml_escape_string("a\\b") == "a\\\\b"


def test_toml_escape_double_quote(ckl_module):
    assert ckl_module._toml_escape_string('say "hi"') == 'say \\"hi\\"'


def test_toml_escape_backspace(ckl_module):
    assert ckl_module._toml_escape_string("\b") == "\\b"


def test_toml_escape_form_feed(ckl_module):
    assert ckl_module._toml_escape_string("\f") == "\\f"


def test_toml_escape_newline(ckl_module):
    assert ckl_module._toml_escape_string("\n") == "\\n"


def test_toml_escape_carriage_return(ckl_module):
    assert ckl_module._toml_escape_string("\r") == "\\r"


def test_toml_escape_tab(ckl_module):
    assert ckl_module._toml_escape_string("\t") == "\\t"


def test_toml_escape_no_double_escaping_backslash_then_quote(ckl_module):
    # A backslash followed by a quote must become \\" not \\\"
    result = ckl_module._toml_escape_string('\\"')
    assert result == '\\\\\\"'


def test_toml_escape_backslash_not_double_escaped(ckl_module):
    # Backslash is escaped first; the resulting \\ must not be re-escaped.
    result = ckl_module._toml_escape_string("\\")
    assert result == "\\\\"
    assert result.count("\\") == 2


def test_toml_escape_unicode_passthrough(ckl_module):
    assert ckl_module._toml_escape_string("héllo ñ 日本語") == "héllo ñ 日本語"


def test_toml_escape_mixed_control_chars(ckl_module):
    result = ckl_module._toml_escape_string("a\tb\nc")
    assert result == "a\\tb\\nc"


# ---------------------------------------------------------------------------
# _toml_kv
# ---------------------------------------------------------------------------

def test_toml_kv_string_value(ckl_module):
    assert ckl_module._toml_kv("HOST_NAME", "myhost") == 'HOST_NAME = "myhost"'


def test_toml_kv_string_with_special_chars_escaped(ckl_module):
    result = ckl_module._toml_kv("NOTE", 'line1\nline2')
    assert result == 'NOTE = "line1\\nline2"'


def test_toml_kv_list_value_toml_array(ckl_module):
    result = ckl_module._toml_kv("CCI_REF", ["CCI-001", "CCI-002"])
    assert result == 'CCI_REF = ["CCI-001", "CCI-002"]'


def test_toml_kv_list_items_escaped(ckl_module):
    result = ckl_module._toml_kv("TAGS", ['a"b', "c\\d"])
    assert result == 'TAGS = [\\"a\\\\\\"b\\", \\"c\\\\\\\\d\\"]' or (
        '\\"' in result and '\\\\' in result
    )


def test_toml_kv_empty_list(ckl_module):
    result = ckl_module._toml_kv("CCI_REF", [])
    assert result == "CCI_REF = []"


def test_toml_kv_single_item_list(ckl_module):
    result = ckl_module._toml_kv("CCI_REF", ["CCI-001"])
    assert result == 'CCI_REF = ["CCI-001"]'


# ---------------------------------------------------------------------------
# build_toml — header and top-level fields
# ---------------------------------------------------------------------------

def test_build_toml_has_header_comment(ckl_module):
    out = ckl_module.build_toml(_make_data())
    assert out.startswith("#")


def test_build_toml_header_contains_source_file(ckl_module):
    out = ckl_module.build_toml(_make_data(source="U_RHEL_8.ckl"))
    assert "U_RHEL_8.ckl" in out.splitlines()[1]


def test_build_toml_top_level_source_file(ckl_module):
    out = ckl_module.build_toml(_make_data(source="scan.ckl"))
    assert 'source_file = "scan.ckl"' in out


def test_build_toml_top_level_converted_at(ckl_module):
    out = ckl_module.build_toml(_make_data(converted="2024-01-15T12:00:00Z"))
    assert 'converted_at = "2024-01-15T12:00:00Z"' in out


# ---------------------------------------------------------------------------
# build_toml — [asset] table
# ---------------------------------------------------------------------------

def test_build_toml_has_asset_table(ckl_module):
    out = ckl_module.build_toml(_make_data())
    assert "[asset]" in out


def test_build_toml_asset_fields_rendered(ckl_module):
    out = ckl_module.build_toml(_make_data(asset={"HOST_NAME": "box", "HOST_IP": "1.2.3.4"}))
    assert 'HOST_NAME = "box"' in out
    assert 'HOST_IP = "1.2.3.4"' in out


def test_build_toml_asset_special_chars_escaped(ckl_module):
    out = ckl_module.build_toml(_make_data(asset={"NOTE": 'line1\nline2'}))
    assert 'NOTE = "line1\\nline2"' in out


def test_build_toml_empty_asset_table_still_present(ckl_module):
    out = ckl_module.build_toml(_make_data(asset={}))
    assert "[asset]" in out


# ---------------------------------------------------------------------------
# build_toml — [[vulnerabilities]] array of tables
# ---------------------------------------------------------------------------

def test_build_toml_no_vulns_no_vulnerabilities_header(ckl_module):
    out = ckl_module.build_toml(_make_data(vulns=[]))
    assert "[[vulnerabilities]]" not in out


def test_build_toml_single_vuln_has_vulnerabilities_header(ckl_module):
    out = ckl_module.build_toml(_make_data(vulns=[_vuln()]))
    assert "[[vulnerabilities]]" in out


def test_build_toml_vuln_count_matches(ckl_module):
    out = ckl_module.build_toml(_make_data(vulns=[_vuln("V-1"), _vuln("V-2")]))
    assert out.count("[[vulnerabilities]]") == 2


def test_build_toml_direct_fields_rendered(ckl_module):
    out = ckl_module.build_toml(_make_data(vulns=[_vuln(status="NotAFinding", finding="All good.")]))
    assert 'STATUS = "NotAFinding"' in out
    assert 'FINDING_DETAILS = "All good."' in out


def test_build_toml_stig_data_subtable_present(ckl_module):
    out = ckl_module.build_toml(_make_data(vulns=[_vuln("V-99")]))
    assert "[vulnerabilities.stig_data]" in out


def test_build_toml_stig_data_subtable_absent_when_empty(ckl_module):
    vuln = _vuln()
    vuln["stig_data"] = {}
    out = ckl_module.build_toml(_make_data(vulns=[vuln]))
    assert "[vulnerabilities.stig_data]" not in out


def test_build_toml_list_value_rendered_as_toml_array(ckl_module):
    out = ckl_module.build_toml(_make_data(vulns=[_vuln(cci_ref=["CCI-001", "CCI-002"])]))
    assert 'CCI_REF = ["CCI-001", "CCI-002"]' in out


def test_build_toml_stig_data_fields_present(ckl_module):
    out = ckl_module.build_toml(_make_data(vulns=[_vuln("V-42", "SV-42_rule", "medium")]))
    assert 'Vuln_Num = "V-42"' in out
    assert 'Rule_ID = "SV-42_rule"' in out
    assert 'Severity = "medium"' in out
