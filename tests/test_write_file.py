"""Tests for write_file() — success path and both error branches."""
import pytest
from pathlib import Path
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

def test_write_file_creates_file_with_correct_content(ckl_module, tmp_path):
    dest = tmp_path / "output.json"
    ckl_module.write_file(dest, '{"key": "value"}', "JSON")
    assert dest.exists()
    assert dest.read_text(encoding="utf-8") == '{"key": "value"}'


def test_write_file_returns_true_on_success(ckl_module, tmp_path):
    dest = tmp_path / "output.json"
    assert ckl_module.write_file(dest, "content", "JSON") is True


def test_write_file_prints_ok_to_stdout(ckl_module, tmp_path, capsys):
    dest = tmp_path / "output.json"
    ckl_module.write_file(dest, "content", "JSON")
    out = capsys.readouterr().out
    assert "[OK]" in out
    assert "JSON" in out


def test_write_file_success_produces_no_stderr(ckl_module, tmp_path, capsys):
    dest = tmp_path / "output.json"
    ckl_module.write_file(dest, "content", "JSON")
    assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# PermissionError branch — prints to stderr, does NOT exit
# ---------------------------------------------------------------------------

def test_write_file_permission_error_does_not_exit(ckl_module):
    mock_path = MagicMock(spec=Path)
    mock_path.write_text.side_effect = PermissionError("denied")
    ckl_module.write_file(mock_path, "content", "JSON")  # must not raise


def test_write_file_permission_error_returns_false(ckl_module):
    mock_path = MagicMock(spec=Path)
    mock_path.write_text.side_effect = PermissionError("denied")
    assert ckl_module.write_file(mock_path, "content", "JSON") is False


def test_write_file_permission_error_prints_to_stderr(ckl_module, capsys):
    mock_path = MagicMock(spec=Path)
    mock_path.write_text.side_effect = PermissionError("denied")
    ckl_module.write_file(mock_path, "content", "JSON")
    err = capsys.readouterr().err
    assert "[ERROR]" in err
    assert "Permission denied" in err


def test_write_file_permission_error_no_stdout(ckl_module, capsys):
    mock_path = MagicMock(spec=Path)
    mock_path.write_text.side_effect = PermissionError("denied")
    ckl_module.write_file(mock_path, "content", "JSON")
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# IOError branch — prints to stderr, does NOT exit
# ---------------------------------------------------------------------------

def test_write_file_ioerror_does_not_exit(ckl_module):
    mock_path = MagicMock(spec=Path)
    mock_path.write_text.side_effect = IOError("disk full")
    ckl_module.write_file(mock_path, "content", "TOML")  # must not raise


def test_write_file_ioerror_returns_false(ckl_module):
    mock_path = MagicMock(spec=Path)
    mock_path.write_text.side_effect = IOError("disk full")
    assert ckl_module.write_file(mock_path, "content", "TOML") is False


def test_write_file_ioerror_prints_to_stderr(ckl_module, capsys):
    mock_path = MagicMock(spec=Path)
    mock_path.write_text.side_effect = IOError("disk full")
    ckl_module.write_file(mock_path, "content", "TOML")
    err = capsys.readouterr().err
    assert "[ERROR]" in err
    assert "I/O error" in err


def test_write_file_ioerror_no_stdout(ckl_module, capsys):
    mock_path = MagicMock(spec=Path)
    mock_path.write_text.side_effect = IOError("disk full")
    ckl_module.write_file(mock_path, "content", "TOML")
    assert capsys.readouterr().out == ""
