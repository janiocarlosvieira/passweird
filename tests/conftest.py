import pytest

# No sys.path hack: passweird is an installed (editable) package once
# `pip install -e ".[dev]"` has been run, so tests import it like any dependency.

@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Redirects ~/.passweird to a throwaway tmp_path for every test so the
    suite never touches the real user's ~/.passweird directory."""
    monkeypatch.setenv("HOME", str(tmp_path))
    yield tmp_path
