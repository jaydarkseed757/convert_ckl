import importlib.util
import pathlib
import sys
from unittest.mock import patch

import pytest

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def ckl_module():
    """Load ckl_convert.py via importlib."""
    src = pathlib.Path(__file__).parent.parent / "ckl_convert.py"
    spec = importlib.util.spec_from_file_location("ckl_convert", src)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ckl_convert"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def fixtures_dir():
    """Path to tests/fixtures/."""
    return _FIXTURES


def copy_fixture(name: str, tmp_path: pathlib.Path) -> pathlib.Path:
    """Copy a fixture file into tmp_path so output files land there, not in fixtures/."""
    src = _FIXTURES / name
    dest = tmp_path / name
    dest.write_bytes(src.read_bytes())
    return dest


def run_main(ckl_module, ckl_path: pathlib.Path, extra_argv: list = None):
    """Invoke main() with sys.argv pointing at ckl_path, running as non-root."""
    argv = ["ckl_convert", str(ckl_path)] + (extra_argv or [])
    with patch("sys.argv", argv), patch("os.geteuid", return_value=1000, create=True):
        return ckl_module.main()
