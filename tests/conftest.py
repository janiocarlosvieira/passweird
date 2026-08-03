import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Redirects ~/.passweird to a throwaway tmp_path for every test so the
    suite never touches the real user's ~/.passweird directory."""
    monkeypatch.setenv("HOME", str(tmp_path))
    yield tmp_path
