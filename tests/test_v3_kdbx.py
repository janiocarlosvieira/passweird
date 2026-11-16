# ADR-0009 §6 - passwords leave the tool only as KDBX, with a declared KDF.
import os
import shutil
import stat
import subprocess
import sys

import pytest

from passweird.v3 import kdbx

pykeepass = pytest.importorskip("pykeepass")

ENTRIES = [
    {"title": "github.com", "username": "fulano", "password": "S3nh@-gerada", "url": "https://github.com",
     "notes": "conta pessoal", "fields": {"passweird_counter": 2, "passweird_length": 18}},
    {"title": "example.org", "username": "", "password": "outra", "fields": {}},
]


def test_export_sets_the_declared_kdf_and_roundtrips(tmp_path):
    path = kdbx.export(str(tmp_path / "out.kdbx"), "senha do arquivo", ENTRIES)
    database = pykeepass.PyKeePass(path, password="senha do arquivo")
    kdf_uuid, memory, iterations, parallelism, salt = kdbx.read_kdf(database)
    assert kdf_uuid == kdbx.KDF_ARGON2ID_UUID
    assert (memory, iterations, parallelism) == (256 * 1024 * 1024, 3, 4)
    assert database.version[0] == 4 and database.kdf_algorithm == "argon2id"
    entry = database.find_entries(title="github.com", first=True)
    assert (entry.username, entry.password, entry.url, entry.notes) == \
        ("fulano", "S3nh@-gerada", "https://github.com", "conta pessoal")
    assert entry.get_custom_property("passweird_counter") == "2"
    assert entry.group.name == "Passweird"
    assert len(database.entries) == 2


def test_the_library_default_is_not_what_gets_written(tmp_path):
    """Why the KDF is set explicitly: the template is Argon2d, 64 MiB, fixed salt."""
    first = pykeepass.create_database(str(tmp_path / "a.kdbx"), password="x")
    assert kdbx.read_kdf(first)[0] != kdbx.KDF_ARGON2ID_UUID
    template_salt = kdbx.read_kdf(first)[4]
    a = kdbx.export(str(tmp_path / "c.kdbx"), "x", ENTRIES)
    b = kdbx.export(str(tmp_path / "d.kdbx"), "x", ENTRIES)
    salt_a = kdbx.read_kdf(pykeepass.PyKeePass(a, password="x"))[4]
    salt_b = kdbx.read_kdf(pykeepass.PyKeePass(b, password="x"))[4]
    assert len({template_salt, salt_a, salt_b}) == 3


def test_export_refuses_to_overwrite_and_leaves_no_temporary(tmp_path):
    path = str(tmp_path / "out.kdbx")
    kdbx.export(path, "x", ENTRIES)
    before = open(path, "rb").read()
    with pytest.raises(kdbx.KdbxError):
        kdbx.export(path, "y", ENTRIES)
    assert open(path, "rb").read() == before
    assert os.listdir(tmp_path) == ["out.kdbx"]


def test_wrong_password_does_not_open(tmp_path):
    path = kdbx.export(str(tmp_path / "out.kdbx"), "certa", ENTRIES)
    with pytest.raises(Exception):
        pykeepass.PyKeePass(path, password="errada")


def test_export_needs_a_password_and_an_existing_directory(tmp_path):
    with pytest.raises(kdbx.KdbxError):
        kdbx.export(str(tmp_path / "out.kdbx"), "", ENTRIES)
    with pytest.raises(kdbx.KdbxError):
        kdbx.export(str(tmp_path / "missing" / "out.kdbx"), "x", ENTRIES)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_export_is_private(tmp_path):
    path = kdbx.export(str(tmp_path / "out.kdbx"), "x", ENTRIES)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.skipif(shutil.which("keepassxc-cli") is None, reason="keepassxc-cli not installed")
def test_keepassxc_opens_the_export(tmp_path):
    """The documented flow ends in KeePassXC, so KeePassXC must read the file."""
    path = kdbx.export(str(tmp_path / "out.kdbx"), "senha do arquivo", ENTRIES)
    listing = subprocess.run(["keepassxc-cli", "ls", "-R", "-q", path], input="senha do arquivo\n",
                             capture_output=True, text=True, timeout=120)
    assert listing.returncode == 0, listing.stderr
    assert "github.com" in listing.stdout and "example.org" in listing.stdout
    info = subprocess.run(["keepassxc-cli", "db-info", "-q", path], input="senha do arquivo\n",
                          capture_output=True, text=True, timeout=120)
    assert info.returncode == 0, info.stderr
    assert "Argon2id" in info.stdout
