"""Tests for check_root() — the UID-0 execution guard."""
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Non-root: function is a no-op
# ---------------------------------------------------------------------------

def test_non_root_does_nothing(ckl_module, capsys):
    """When not running as root the function returns None with no output."""
    with patch("os.geteuid", return_value=1000):
        result = ckl_module.check_root(allow_root=False)

    assert result is None
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_non_root_allow_root_flag_is_irrelevant(ckl_module, capsys):
    """allow_root=True has no effect when not running as root."""
    with patch("os.geteuid", return_value=500):
        result = ckl_module.check_root(allow_root=True)

    assert result is None
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


# ---------------------------------------------------------------------------
# Root without --run-as-root: must exit with code 1
# ---------------------------------------------------------------------------

def test_root_without_flag_exits(ckl_module):
    """Running as root without allow_root=True must call sys.exit(1)."""
    with patch("os.geteuid", return_value=0):
        with pytest.raises(SystemExit) as exc_info:
            ckl_module.check_root(allow_root=False)

    assert exc_info.value.code == 1


def test_root_without_flag_prints_security_error(ckl_module, capsys):
    """The exit message should go to stderr and mention the security risk."""
    with patch("os.geteuid", return_value=0):
        try:
            ckl_module.check_root(allow_root=False)
        except SystemExit:
            pass

    err = capsys.readouterr().err
    assert "[SECURITY ERROR]" in err
    assert "--run-as-root" in err


def test_root_without_flag_produces_no_stdout(ckl_module, capsys):
    """Error output must go to stderr only, not stdout."""
    with patch("os.geteuid", return_value=0):
        try:
            ckl_module.check_root(allow_root=False)
        except SystemExit:
            pass

    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Root with --run-as-root: must warn but not exit
# ---------------------------------------------------------------------------

def test_root_with_flag_does_not_exit(ckl_module):
    """Running as root with allow_root=True must not raise SystemExit."""
    with patch("os.geteuid", return_value=0):
        result = ckl_module.check_root(allow_root=True)

    assert result is None


def test_root_with_flag_prints_warning(ckl_module, capsys):
    """A security warning must be emitted to stderr when bypassing the guard."""
    with patch("os.geteuid", return_value=0):
        ckl_module.check_root(allow_root=True)

    err = capsys.readouterr().err
    assert "[SECURITY WARNING]" in err
    assert "--run-as-root" in err


def test_root_with_flag_produces_no_stdout(ckl_module, capsys):
    """Warning output must go to stderr only, not stdout."""
    with patch("os.geteuid", return_value=0):
        ckl_module.check_root(allow_root=True)

    assert capsys.readouterr().out == ""
