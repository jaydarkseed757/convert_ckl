"""Tests for validate_input() — all 5 branches."""
import pytest
from pathlib import Path
from unittest.mock import patch


def _make_valid_ckl(tmp_path: Path) -> Path:
    f = tmp_path / "test.ckl"
    f.write_bytes(b"<CHECKLIST/>")
    return f


# ---------------------------------------------------------------------------
# Branch 1: file does not exist
# ---------------------------------------------------------------------------

def test_validate_input_missing_file_exits(ckl_module, tmp_path):
    ghost = tmp_path / "ghost.ckl"
    with pytest.raises(SystemExit) as exc_info:
        ckl_module.validate_input(str(ghost))
    assert exc_info.value.code == 1


def test_validate_input_missing_file_stderr(ckl_module, tmp_path, capsys):
    ghost = tmp_path / "ghost.ckl"
    try:
        ckl_module.validate_input(str(ghost))
    except SystemExit:
        pass
    err = capsys.readouterr().err
    assert "[ERROR]" in err
    assert "not found" in err
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Branch 2: path is not a regular file (directory)
# ---------------------------------------------------------------------------

def test_validate_input_directory_exits(ckl_module, tmp_path):
    with pytest.raises(SystemExit) as exc_info:
        ckl_module.validate_input(str(tmp_path))
    assert exc_info.value.code == 1


def test_validate_input_directory_stderr(ckl_module, tmp_path, capsys):
    try:
        ckl_module.validate_input(str(tmp_path))
    except SystemExit:
        pass
    err = capsys.readouterr().err
    assert "[ERROR]" in err
    assert "not a regular file" in err


# ---------------------------------------------------------------------------
# Branch 3: no read permission (mocked — container runs as root)
# ---------------------------------------------------------------------------

def test_validate_input_no_read_permission_exits(ckl_module, tmp_path):
    f = _make_valid_ckl(tmp_path)
    with patch("os.access", return_value=False):
        with pytest.raises(SystemExit) as exc_info:
            ckl_module.validate_input(str(f))
    assert exc_info.value.code == 1


def test_validate_input_no_read_permission_stderr(ckl_module, tmp_path, capsys):
    f = _make_valid_ckl(tmp_path)
    with patch("os.access", return_value=False):
        try:
            ckl_module.validate_input(str(f))
        except SystemExit:
            pass
    err = capsys.readouterr().err
    assert "[ERROR]" in err
    assert "No read permission" in err


# ---------------------------------------------------------------------------
# Branch 4: file exists but is empty
# ---------------------------------------------------------------------------

def test_validate_input_empty_file_exits(ckl_module, tmp_path):
    f = tmp_path / "empty.ckl"
    f.write_bytes(b"")
    with pytest.raises(SystemExit) as exc_info:
        ckl_module.validate_input(str(f))
    assert exc_info.value.code == 1


def test_validate_input_empty_file_stderr(ckl_module, tmp_path, capsys):
    f = tmp_path / "empty.ckl"
    f.write_bytes(b"")
    try:
        ckl_module.validate_input(str(f))
    except SystemExit:
        pass
    err = capsys.readouterr().err
    assert "[ERROR]" in err
    assert "empty" in err


# ---------------------------------------------------------------------------
# Branch 5: unexpected extension — warns but does NOT exit
# ---------------------------------------------------------------------------

def test_validate_input_bad_extension_warns(ckl_module, tmp_path, capsys):
    f = tmp_path / "data.txt"
    f.write_bytes(b"<x/>")
    ckl_module.validate_input(str(f))  # must not raise
    err = capsys.readouterr().err
    assert "[WARNING]" in err
    assert ".txt" in err


def test_validate_input_bad_extension_returns_path(ckl_module, tmp_path):
    f = tmp_path / "data.txt"
    f.write_bytes(b"<x/>")
    result = ckl_module.validate_input(str(f))
    assert isinstance(result, Path)
    assert result == f.resolve()


def test_validate_input_bad_extension_no_stdout(ckl_module, tmp_path, capsys):
    f = tmp_path / "data.txt"
    f.write_bytes(b"<x/>")
    ckl_module.validate_input(str(f))
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Happy path: valid .ckl file
# ---------------------------------------------------------------------------

def test_validate_input_valid_ckl_returns_path(ckl_module, tmp_path):
    f = _make_valid_ckl(tmp_path)
    result = ckl_module.validate_input(str(f))
    assert isinstance(result, Path)
    assert result == f.resolve()


def test_validate_input_valid_ckl_no_output(ckl_module, tmp_path, capsys):
    f = _make_valid_ckl(tmp_path)
    ckl_module.validate_input(str(f))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_validate_input_valid_chk_extension(ckl_module, tmp_path):
    f = tmp_path / "test.chk"
    f.write_bytes(b"<CHECKLIST/>")
    result = ckl_module.validate_input(str(f))
    assert isinstance(result, Path)
