import importlib.util
import pathlib
import sys

import pytest


@pytest.fixture(scope="session")
def ckl_module():
    """Load 'ckl convert.py' (space in filename) via importlib."""
    src = pathlib.Path(__file__).parent.parent / "ckl_convert.py"
    spec = importlib.util.spec_from_file_location("ckl_convert", src)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ckl_convert"] = mod
    spec.loader.exec_module(mod)
    return mod
