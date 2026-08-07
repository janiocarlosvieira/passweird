import os

import pytest

# No sys.path hack: passweird is an installed (editable) package once
# `pip install -e ".[dev]"` has been run, so tests import it like any dependency.


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """
    Redirects ~/.passweird to a throwaway tmp_path for every test so the suite
    never touches the real user's ~/.passweird directory.

    Setting HOME alone is not enough: os.path.expanduser ignores HOME entirely on
    Windows. ntpath consults USERPROFILE first, then HOMEDRIVE + HOMEPATH, and
    never falls back to HOME. Without the variables below, every test on Windows
    resolved "~" to the real user profile - so the suite wrote into the developer's
    actual ~/.passweird and tests saw each other's logs and registered master
    hashes, which is exactly how 18 of them failed on the first CI run.
    """
    monkeypatch.setenv("HOME", str(tmp_path))

    drive, tail = os.path.splitdrive(str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOMEDRIVE", drive)
    monkeypatch.setenv("HOMEPATH", tail)

    yield tmp_path
