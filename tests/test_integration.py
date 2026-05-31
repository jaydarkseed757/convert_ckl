"""End-to-end integration tests for the full conversion pipeline (main())."""
import json
import pathlib
import pytest
from pathlib import Path
from unittest.mock import patch

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _copy_fixture(name: str, tmp_path: Path) -> Path:
    """Copy a fixture file into tmp_path so output files land there, not in fixtures/."""
    src = _FIXTURES / name
    dest = tmp_path / name
    dest.write_bytes(src.read_bytes())
    return dest


def _run_main(ckl_module, ckl_path: Path, extra_argv: list = None):
    """Invoke main() with sys.argv pointing at ckl_path, running as non-root."""
    argv = ["ckl_convert", str(ckl_path)] + (extra_argv or [])
    with patch("sys.argv", argv), patch("os.geteuid", return_value=1000):
        return ckl_module.main()


# ---------------------------------------------------------------------------
# Happy path: full pipeline with a realistic fixture
# ---------------------------------------------------------------------------

def test_integration_main_returns_zero(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    assert _run_main(ckl_module, f) == 0


def test_integration_all_three_output_files_created(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    assert (tmp_path / "valid.json").exists()
    assert (tmp_path / "valid.toml").exists()
    assert (tmp_path / "valid.md").exists()


def test_integration_output_files_in_same_dir_as_input(ckl_module, tmp_path):
    subdir = tmp_path / "scans"
    subdir.mkdir()
    f = _copy_fixture("valid.ckl", subdir)
    _run_main(ckl_module, f)
    assert (subdir / "valid.json").exists()
    assert (subdir / "valid.toml").exists()
    assert (subdir / "valid.md").exists()


# ---------------------------------------------------------------------------
# JSON output correctness
# ---------------------------------------------------------------------------

def test_integration_json_is_valid_and_has_expected_keys(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "valid.json").read_text(encoding="utf-8"))
    assert set(data.keys()) == {"source_file", "converted_at", "asset", "vulnerabilities"}


def test_integration_json_asset_fields(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "valid.json").read_text(encoding="utf-8"))
    assert data["asset"]["HOST_NAME"] == "rhel8-node01"
    assert data["asset"]["HOST_IP"] == "192.168.1.10"


def test_integration_json_vulnerabilities(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    data = json.loads((tmp_path / "valid.json").read_text(encoding="utf-8"))
    assert len(data["vulnerabilities"]) == 3
    v0 = data["vulnerabilities"][0]
    assert v0["STATUS"] == "NotAFinding"
    assert v0["stig_data"]["Vuln_Num"] == "V-230221"
    # Repeated CCI_REF must survive as a list through the full pipeline
    assert v0["stig_data"]["CCI_REF"] == ["CCI-000366", "CCI-001199"]


# ---------------------------------------------------------------------------
# TOML output correctness
# ---------------------------------------------------------------------------

def test_integration_toml_has_asset_table(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "valid.toml").read_text(encoding="utf-8")
    assert "[asset]" in content
    assert "HOST_NAME" in content


def test_integration_toml_has_vulnerabilities_array(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "valid.toml").read_text(encoding="utf-8")
    assert "[[vulnerabilities]]" in content


def test_integration_toml_vuln_count_matches(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "valid.toml").read_text(encoding="utf-8")
    assert content.count("[[vulnerabilities]]") == 3


# ---------------------------------------------------------------------------
# Markdown output correctness
# ---------------------------------------------------------------------------

def test_integration_markdown_has_title(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "valid.md").read_text(encoding="utf-8")
    assert content.startswith("#")
    assert "rhel8-node01" in content


def test_integration_markdown_has_expected_sections(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "valid.md").read_text(encoding="utf-8")
    assert "## Asset Information" in content
    assert "## Vulnerability Summary" in content
    assert "## Detailed Findings" in content


def test_integration_markdown_status_counts(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    content = (tmp_path / "valid.md").read_text(encoding="utf-8")
    # valid.ckl has: 1 NotAFinding, 1 Open, 1 Not Applicable
    assert "NotAFinding" in content
    assert "Open" in content
    assert "Not Applicable" in content


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


# ---------------------------------------------------------------------------
# Write failure → exit code 1
# ---------------------------------------------------------------------------

def test_integration_write_failure_returns_one(ckl_module, tmp_path, capsys):
    f = _copy_fixture("valid.ckl", tmp_path)
    # Patch write_file to simulate a JSON write failure.
    original = ckl_module.write_file
    call_count = {"n": 0}

    def failing_write(path, content, label):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return False
        return original(path, content, label)

    with patch("sys.argv", ["ckl_convert", str(f)]), \
         patch("os.geteuid", return_value=1000), \
         patch.object(ckl_module, "write_file", side_effect=failing_write):
        result = ckl_module.main()

    assert result == 1


def test_integration_write_failure_prints_error_to_stderr(ckl_module, tmp_path, capsys):
    f = _copy_fixture("valid.ckl", tmp_path)

    with patch("sys.argv", ["ckl_convert", str(f)]), \
         patch("os.geteuid", return_value=1000), \
         patch.object(ckl_module, "write_file", return_value=False):
        ckl_module.main()

    assert "[ERROR]" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# --report flag (opt-in)
# ---------------------------------------------------------------------------

def test_integration_report_flag_creates_report_file(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    result = _run_main(ckl_module, f, ["--report"])
    assert result == 0
    assert (tmp_path / "report_valid.txt").exists()


def test_integration_report_not_created_without_flag(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    assert not (tmp_path / "report_valid.txt").exists()


def test_integration_report_contains_breakdown_sections(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_valid.txt").read_text(encoding="utf-8")
    assert "Status Breakdown" in content
    assert "Severity Breakdown" in content


def test_integration_report_counts_match_fixture(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    content = (tmp_path / "report_valid.txt").read_text(encoding="utf-8")
    # valid.ckl: 3 findings; 1 each high/medium/low; NotAFinding/Open/Not Applicable
    assert "Total findings : 3" in content
    assert "CAT I (high)" in content
    assert "CAT II (medium)" in content
    assert "CAT III (low)" in content
    assert "NotAFinding" in content
    assert "Open" in content
    assert "Not Applicable" in content


def test_integration_default_outputs_still_written_with_report(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--report"])
    # Additive: JSON/TOML/MD must still be produced.
    assert (tmp_path / "valid.json").exists()
    assert (tmp_path / "valid.toml").exists()
    assert (tmp_path / "valid.md").exists()


# ---------------------------------------------------------------------------
# --prompt flag
# ---------------------------------------------------------------------------

def test_integration_prompt_flag_creates_prompt_file(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    result = _run_main(ckl_module, f, ["--prompt"])
    assert result == 0
    assert (tmp_path / "prompt_valid.md").exists()


def test_integration_prompt_not_created_without_flag(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f)
    assert not (tmp_path / "prompt_valid.md").exists()


def test_integration_prompt_contains_system_prompt(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--prompt"])
    content = (tmp_path / "prompt_valid.md").read_text(encoding="utf-8")
    assert "STIG compliance analyst" in content


def test_integration_prompt_contains_markdown_output(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--prompt"])
    content = (tmp_path / "prompt_valid.md").read_text(encoding="utf-8")
    assert "rhel8-node01" in content


def test_integration_prompt_default_outputs_still_written(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--prompt"])
    assert (tmp_path / "valid.json").exists()
    assert (tmp_path / "valid.toml").exists()
    assert (tmp_path / "valid.md").exists()


# ---------------------------------------------------------------------------
# --chunk flag
# ---------------------------------------------------------------------------

def test_integration_chunk_creates_chunk_files(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    # valid.ckl has 3 vulns; --chunk 2 → chunks 001 (2 vulns) and 002 (1 vuln)
    result = _run_main(ckl_module, f, ["--chunk", "2"])
    assert result == 0
    assert (tmp_path / "valid_chunk_001.md").exists()
    assert (tmp_path / "valid_chunk_002.md").exists()


def test_integration_chunk_correct_count(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--chunk", "2"])
    chunks = sorted(tmp_path.glob("valid_chunk_*.md"))
    assert len(chunks) == 2


def test_integration_chunk_larger_than_total_gives_one_file(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--chunk", "10"])
    chunks = sorted(tmp_path.glob("valid_chunk_*.md"))
    assert len(chunks) == 1


def test_integration_chunk_files_contain_asset_info(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--chunk", "2"])
    for chunk in sorted(tmp_path.glob("valid_chunk_*.md")):
        assert "rhel8-node01" in chunk.read_text(encoding="utf-8")


def test_integration_chunk_files_cover_all_vulns(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--chunk", "2"])
    combined = "".join(
        p.read_text(encoding="utf-8") for p in sorted(tmp_path.glob("valid_chunk_*.md"))
    )
    assert "V-230221" in combined
    assert "V-230222" in combined
    assert "V-230223" in combined


def test_integration_chunk_regular_md_still_written(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    _run_main(ckl_module, f, ["--chunk", "2"])
    assert (tmp_path / "valid.md").exists()


def test_integration_chunk_zero_returns_one(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    result = _run_main(ckl_module, f, ["--chunk", "0"])
    assert result == 1


# ---------------------------------------------------------------------------
# --quiet flag
# ---------------------------------------------------------------------------

def test_integration_quiet_suppresses_warning(ckl_module, tmp_path, capsys):
    no_vulns = "<CHECKLIST><ASSET><HOST_NAME>box</HOST_NAME></ASSET></CHECKLIST>"
    f = tmp_path / "empty_vulns.ckl"
    f.write_text(no_vulns, encoding="utf-8")
    _run_main(ckl_module, f, ["--quiet"])
    assert capsys.readouterr().err == ""


def test_integration_no_quiet_still_shows_warning(ckl_module, tmp_path, capsys):
    no_vulns = "<CHECKLIST><ASSET><HOST_NAME>box</HOST_NAME></ASSET></CHECKLIST>"
    f = tmp_path / "empty_vulns.ckl"
    f.write_text(no_vulns, encoding="utf-8")
    _run_main(ckl_module, f)
    assert "[WARNING]" in capsys.readouterr().err


def test_integration_quiet_still_shows_error(ckl_module, tmp_path, capsys):
    f = _copy_fixture("valid.ckl", tmp_path)
    from unittest.mock import patch
    with patch("sys.argv", ["ckl_convert", str(f), "--quiet"]), \
         patch("os.geteuid", return_value=1000), \
         patch.object(ckl_module, "write_file", return_value=False):
        ckl_module.main()
    assert "[ERROR]" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# --output-dir flag
# ---------------------------------------------------------------------------

def test_integration_output_dir_writes_files_there(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    out = tmp_path / "out"
    result = _run_main(ckl_module, f, ["--output-dir", str(out)])
    assert result == 0
    assert (out / "valid.json").exists()
    assert (out / "valid.toml").exists()
    assert (out / "valid.md").exists()


def test_integration_output_dir_created_if_missing(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    out = tmp_path / "new" / "nested" / "dir"
    assert not out.exists()
    _run_main(ckl_module, f, ["--output-dir", str(out)])
    assert out.exists()


def test_integration_output_dir_not_alongside_input(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    out = tmp_path / "out"
    _run_main(ckl_module, f, ["--output-dir", str(out)])
    # Files must NOT appear next to the input file
    assert not (tmp_path / "valid.json").exists()


def test_integration_output_dir_with_report(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    out = tmp_path / "out"
    _run_main(ckl_module, f, ["--output-dir", str(out), "--report"])
    assert (out / "report_valid.txt").exists()


def test_integration_output_dir_with_chunk(ckl_module, tmp_path):
    f = _copy_fixture("valid.ckl", tmp_path)
    out = tmp_path / "out"
    _run_main(ckl_module, f, ["--output-dir", str(out), "--chunk", "2"])
    assert (out / "valid_chunk_001.md").exists()
    assert (out / "valid_chunk_002.md").exists()
