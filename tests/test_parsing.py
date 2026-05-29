"""Tests for parse_asset(), parse_vulnerabilities(), and parse_ckl()."""
import re
import xml.etree.ElementTree as ET
import pytest
from pathlib import Path


# ---------------------------------------------------------------------------
# parse_asset
# ---------------------------------------------------------------------------

def test_parse_asset_no_asset_node_returns_empty_dict(ckl_module):
    root = ET.fromstring("<CHECKLIST></CHECKLIST>")
    assert ckl_module.parse_asset(root) == {}


def test_parse_asset_other_children_but_no_asset(ckl_module):
    root = ET.fromstring("<CHECKLIST><VULN><STATUS>Open</STATUS></VULN></CHECKLIST>")
    assert ckl_module.parse_asset(root) == {}


def test_parse_asset_populates_dict_from_children(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST>"
        "<ASSET><HOST_NAME>myhost</HOST_NAME><HOST_IP>10.0.0.1</HOST_IP></ASSET>"
        "</CHECKLIST>"
    )
    result = ckl_module.parse_asset(root)
    assert result == {"HOST_NAME": "myhost", "HOST_IP": "10.0.0.1"}


def test_parse_asset_strips_whitespace(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST><ASSET><HOST_NAME>  myhost  </HOST_NAME></ASSET></CHECKLIST>"
    )
    assert ckl_module.parse_asset(root)["HOST_NAME"] == "myhost"


def test_parse_asset_empty_text_becomes_empty_string(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST><ASSET><HOST_IP></HOST_IP></ASSET></CHECKLIST>"
    )
    assert ckl_module.parse_asset(root)["HOST_IP"] == ""


def test_parse_asset_returns_dict_type(ckl_module):
    root = ET.fromstring("<CHECKLIST><ASSET><X>y</X></ASSET></CHECKLIST>")
    assert isinstance(ckl_module.parse_asset(root), dict)


# ---------------------------------------------------------------------------
# parse_vulnerabilities
# ---------------------------------------------------------------------------

def test_parse_vulnerabilities_no_vuln_returns_empty_list(ckl_module):
    root = ET.fromstring("<CHECKLIST></CHECKLIST>")
    result = ckl_module.parse_vulnerabilities(root)
    assert result == []
    assert isinstance(result, list)


def test_parse_vulnerabilities_single_vuln_full(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST><VULN>"
        "<STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>V-1234</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS>NotAFinding</STATUS>"
        "<FINDING_DETAILS>No issues found</FINDING_DETAILS>"
        "<COMMENTS>Reviewed 2024</COMMENTS>"
        "<SEVERITY_OVERRIDE>low</SEVERITY_OVERRIDE>"
        "<SEVERITY_JUSTIFICATION>Mitigated</SEVERITY_JUSTIFICATION>"
        "</VULN></CHECKLIST>"
    )
    result = ckl_module.parse_vulnerabilities(root)
    assert len(result) == 1
    v = result[0]
    assert v["stig_data"]["Vuln_Num"] == "V-1234"
    assert v["STATUS"] == "NotAFinding"
    assert v["FINDING_DETAILS"] == "No issues found"
    assert v["COMMENTS"] == "Reviewed 2024"
    assert v["SEVERITY_OVERRIDE"] == "low"
    assert v["SEVERITY_JUSTIFICATION"] == "Mitigated"


def test_parse_vulnerabilities_empty_attr_name_is_skipped(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST><VULN>"
        "<STIG_DATA><VULN_ATTRIBUTE></VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>should be ignored</ATTRIBUTE_DATA></STIG_DATA>"
        "<STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>V-999</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS></STATUS><FINDING_DETAILS></FINDING_DETAILS>"
        "<COMMENTS></COMMENTS><SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>"
        "<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>"
        "</VULN></CHECKLIST>"
    )
    result = ckl_module.parse_vulnerabilities(root)
    stig = result[0]["stig_data"]
    assert "" not in stig
    assert stig["Vuln_Num"] == "V-999"
    assert len(stig) == 1


def test_parse_vulnerabilities_first_occurrence_is_scalar(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST><VULN>"
        "<STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>CCI-001234</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS></STATUS><FINDING_DETAILS></FINDING_DETAILS>"
        "<COMMENTS></COMMENTS><SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>"
        "<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>"
        "</VULN></CHECKLIST>"
    )
    result = ckl_module.parse_vulnerabilities(root)
    val = result[0]["stig_data"]["CCI_REF"]
    assert val == "CCI-001234"
    assert isinstance(val, str)


def test_parse_vulnerabilities_duplicate_key_becomes_list(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST><VULN>"
        "<STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>CCI-001</ATTRIBUTE_DATA></STIG_DATA>"
        "<STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>CCI-002</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS></STATUS><FINDING_DETAILS></FINDING_DETAILS>"
        "<COMMENTS></COMMENTS><SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>"
        "<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>"
        "</VULN></CHECKLIST>"
    )
    result = ckl_module.parse_vulnerabilities(root)
    val = result[0]["stig_data"]["CCI_REF"]
    assert isinstance(val, list)
    assert val == ["CCI-001", "CCI-002"]


def test_parse_vulnerabilities_triple_duplicate_appends_to_list(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST><VULN>"
        "<STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>CCI-001</ATTRIBUTE_DATA></STIG_DATA>"
        "<STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>CCI-002</ATTRIBUTE_DATA></STIG_DATA>"
        "<STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>CCI-003</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS></STATUS><FINDING_DETAILS></FINDING_DETAILS>"
        "<COMMENTS></COMMENTS><SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>"
        "<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>"
        "</VULN></CHECKLIST>"
    )
    result = ckl_module.parse_vulnerabilities(root)
    val = result[0]["stig_data"]["CCI_REF"]
    assert val == ["CCI-001", "CCI-002", "CCI-003"]
    assert len(val) == 3


def test_parse_vulnerabilities_missing_optional_fields_default_to_empty(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST><VULN>"
        "<STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>"
        "</VULN></CHECKLIST>"
    )
    result = ckl_module.parse_vulnerabilities(root)
    v = result[0]
    assert v["STATUS"] == ""
    assert v["FINDING_DETAILS"] == ""
    assert v["COMMENTS"] == ""
    assert v["SEVERITY_OVERRIDE"] == ""
    assert v["SEVERITY_JUSTIFICATION"] == ""


def test_parse_vulnerabilities_multiple_vulns(ckl_module):
    root = ET.fromstring(
        "<CHECKLIST>"
        "<VULN><STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS>Open</STATUS><FINDING_DETAILS></FINDING_DETAILS>"
        "<COMMENTS></COMMENTS><SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>"
        "<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION></VULN>"
        "<VULN><STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>V-2</ATTRIBUTE_DATA></STIG_DATA>"
        "<STATUS>NotAFinding</STATUS><FINDING_DETAILS></FINDING_DETAILS>"
        "<COMMENTS></COMMENTS><SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>"
        "<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION></VULN>"
        "</CHECKLIST>"
    )
    result = ckl_module.parse_vulnerabilities(root)
    assert len(result) == 2
    assert result[0]["stig_data"]["Vuln_Num"] == "V-1"
    assert result[1]["stig_data"]["Vuln_Num"] == "V-2"
    assert result[0]["STATUS"] == "Open"
    assert result[1]["STATUS"] == "NotAFinding"


# ---------------------------------------------------------------------------
# parse_ckl
# ---------------------------------------------------------------------------

def test_parse_ckl_returns_expected_keys(ckl_module, fixtures_dir):
    result = ckl_module.parse_ckl(fixtures_dir / "minimal.ckl")
    assert isinstance(result, dict)
    assert set(result.keys()) == {"source_file", "converted_at", "asset", "vulnerabilities"}


def test_parse_ckl_source_file_is_filename_only(ckl_module, fixtures_dir):
    result = ckl_module.parse_ckl(fixtures_dir / "minimal.ckl")
    assert result["source_file"] == "minimal.ckl"
    assert "/" not in result["source_file"]


def test_parse_ckl_converted_at_is_iso8601_utc(ckl_module, fixtures_dir):
    result = ckl_module.parse_ckl(fixtures_dir / "minimal.ckl")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", result["converted_at"])


def test_parse_ckl_asset_is_dict(ckl_module, fixtures_dir):
    result = ckl_module.parse_ckl(fixtures_dir / "minimal.ckl")
    assert isinstance(result["asset"], dict)
    assert result["asset"]["HOST_NAME"] == "minimal-host"


def test_parse_ckl_vulnerabilities_is_list(ckl_module, fixtures_dir):
    result = ckl_module.parse_ckl(fixtures_dir / "minimal.ckl")
    assert isinstance(result["vulnerabilities"], list)
    assert len(result["vulnerabilities"]) == 1


def test_parse_ckl_valid_fixture_has_repeated_cci_ref(ckl_module, fixtures_dir):
    result = ckl_module.parse_ckl(fixtures_dir / "valid.ckl")
    v0 = result["vulnerabilities"][0]
    assert v0["stig_data"]["CCI_REF"] == ["CCI-000366", "CCI-001199"]


def test_parse_ckl_invalid_xml_exits(ckl_module, fixtures_dir):
    with pytest.raises(SystemExit) as exc_info:
        ckl_module.parse_ckl(fixtures_dir / "malformed.ckl")
    assert exc_info.value.code == 1


def test_parse_ckl_invalid_xml_stderr(ckl_module, fixtures_dir, capsys):
    try:
        ckl_module.parse_ckl(fixtures_dir / "malformed.ckl")
    except SystemExit:
        pass
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.err
    assert "XML parse error" in captured.err
    assert captured.out == ""
