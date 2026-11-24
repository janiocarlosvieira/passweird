# ADR-0009 §11 - migration from the v2 engine. The v2 state is produced with the
# real v2 functions, then read back through the v3 command line.
import os

import pytest

from passweird import crypto, storage
from passweird.v3 import migrate
from test_v3_cli import ACCESS, BOOST, MASTER, SECRETS, USER, cli, fast, ready  # noqa: F401

V2_MASTER = "senha mestra antiga"
CONTEXTS = ["github.com", "ufpb-sigaa", "https://WWW.Example.org/login", "minha conta do banco",
            "GitHub.com", "pin-do-cartao", "com-temporal"]


@pytest.fixture
def v2_state(isolated_home, tmp_path):
    """hosts.enc, an encrypted log, master.hash, fido2.cred and a CSV export."""
    master_hash = crypto.modified_hash(V2_MASTER)
    source = tmp_path / "hosts.txt"
    source.write_text("\n".join(CONTEXTS) + "\n", encoding="utf-8")
    storage.encrypt_and_save_hosts(master_hash, str(source))

    def log(context, length=18, feat="1111", temporal=""):
        app_hash = crypto.modified_hash(context)
        password = crypto.generate_password(
            "v2", master_hash, app_hash, length, temporal_salt=temporal, use_lower=feat[0] == "1",
            use_upper=feat[1] == "1", use_digits=feat[2] == "1", use_special=feat[3] == "1")
        storage.build_and_log_line("20260801120000", length, master_hash, app_hash, password, feat,
                                   temporal_secret=temporal, print_hash=False)
        return password

    passwords = {
        "github.com": log("github.com", 24, "1110"),
        "pin-do-cartao": log("pin-do-cartao", 6, "0010"),
        "com-temporal": log("com-temporal", temporal="2026/01"),
    }
    log("github.com", 20, "1111")                       # older settings, superseded below
    passwords["github.com"] = log("github.com", 24, "1110")
    log("site-fora-da-lista")                           # in the log, not in hosts.enc
    passwords["ufpb-sigaa"] = crypto.generate_password("v2", master_hash, crypto.modified_hash("ufpb-sigaa"), 18)
    storage.save_master_hash(master_hash)
    storage.export_to_csv("chrome", "x", "https://x", "u", "senha-em-claro")
    (isolated_home / ".passweird" / "fido2.cred").write_bytes(b"credential-id")
    return passwords


def _v2_files(home):
    return sorted(n for n in os.listdir(home / ".passweird") if n != "v3")


def test_migration_imports_sites_and_recovers_settings(ready, v2_state, cli, isolated_home):
    result = cli(["--migrate-v2", "--keep-v2-files"], secrets=[V2_MASTER, ACCESS])
    assert result.code == 0, result.err
    assert "Sites imported: 5; already in the journal: 0; rejected: 2." in result.out
    assert "'minha conta do banco'" in result.out                       # no canonical form
    assert "'GitHub.com'" in result.out and "same canonical site" in result.out
    assert "settings recovered for 3 site(s)" in result.out
    assert "1 context(s) in the log are not in the site list" in result.out
    assert "--fido2 cannot be reproduced" in result.out
    assert "do NOT reuse it as the v3 master" in result.out

    listing = cli(["--list"], secrets=[ACCESS]).out
    assert "github.com  - counter 1, length 24, classes 7" in listing           # from the LAST log record
    assert "pin-do-cartao  - counter 1, length 6, classes 4" in listing
    assert "example.org  - counter 1, length 18, classes 15" in listing        # canonicalised, no log record
    assert "ufpb-sigaa  - counter 1, length 18, classes 15" in listing
    shown = cli(["--show", "example.org"], secrets=[ACCESS]).out
    assert "origin: v2" in shown and "v2_context: https://WWW.Example.org/login" in shown
    assert "temporal secret" in cli(["--show", "com-temporal"], secrets=[ACCESS]).out
    assert len(_v2_files(isolated_home)) == 5                                   # nothing deleted


def test_migration_is_idempotent(ready, v2_state, cli):
    cli(["--migrate-v2", "--keep-v2-files"], secrets=[V2_MASTER, ACCESS])
    again = cli(["--migrate-v2", "--keep-v2-files"], secrets=[V2_MASTER, ACCESS])
    assert "Sites imported: 0; already in the journal: 5" in again.out


def test_wrong_v2_master_changes_nothing(ready, v2_state, cli, isolated_home):
    before = _v2_files(isolated_home)
    result = cli(["--migrate-v2"], secrets=["errada", ACCESS], inputs=["y"])
    assert result.code == 1 and "does not open" in result.err
    assert _v2_files(isolated_home) == before
    assert "empty" in cli(["--list"], secrets=[ACCESS]).out


def test_v2_files_are_deleted_only_on_confirmation(ready, v2_state, cli, isolated_home):
    declined = cli(["--migrate-v2"], secrets=[V2_MASTER, ACCESS], inputs=["n"])
    assert declined.code == 0 and "master.hash" in declined.out and "Kept." in declined.out
    assert "master.hash" in _v2_files(isolated_home)
    accepted = cli(["--migrate-v2"], secrets=[V2_MASTER, ACCESS], inputs=["y"])
    assert accepted.code == 0 and "Deleted 5 file(s)." in accepted.out
    assert _v2_files(isolated_home) == []                                        # csv, log, hash, hosts, cred
    assert "github.com" in cli(["--list"], secrets=[ACCESS]).out                # the journal survived
    # With the v2 files gone there is nothing left to migrate or to ask about.
    rerun = cli(["--migrate-v2"], secrets=[V2_MASTER, ACCESS])
    assert rerun.code == 0 and "No hosts.enc found" in rerun.out


def test_a_named_profile_leaves_the_shared_v2_files_to_default(fast, v2_state, cli, isolated_home):
    # ADR-0013 §5: a command acts on the selected profile and on nothing else.
    work = ["--profile", "work"]
    assert cli(work + ["--init", "--user-id", USER], secrets=[MASTER, MASTER, BOOST, BOOST, ACCESS, ACCESS]).code == 0
    result = cli(work + ["--migrate-v2"], secrets=[V2_MASTER, ACCESS], inputs=["y"])
    assert result.code == 0 and "Sites imported: 5" in result.out
    assert "shared by every profile" in result.out and "default profile" in result.out
    assert len(_v2_files(isolated_home)) == 5                       # kept, though a "y" was ready


def test_old_and_new_passwords_go_to_kdbx(ready, v2_state, cli, tmp_path):
    pykeepass = pytest.importorskip("pykeepass")
    out = tmp_path / "pairs.kdbx"
    result = cli(["--migrate-v2", "--keep-v2-files", "--export-kdbx", str(out)],
                 secrets=[V2_MASTER, "", MASTER, BOOST, ACCESS, "k", "k"])
    assert result.code == 0, result.err
    database = pykeepass.PyKeePass(str(out), password="k")
    for site in ("github.com", "pin-do-cartao", "ufpb-sigaa"):
        assert database.find_entries(title=f"{site} (v2)", first=True).password == v2_state[site]
    new = database.find_entries(title="github.com (v3)", first=True).password
    assert new == cli(["github.com"], secrets=SECRETS).password and new != v2_state["github.com"]
    # The temporal secret was not given: that v2 password is not invented.
    assert database.find_entries(title="com-temporal (v2)", first=True) is None
    assert database.find_entries(title="com-temporal (v3)", first=True) is not None
    assert "NOT exported" in result.out
    for password in v2_state.values():
        assert password not in result.out


def test_temporal_secret_makes_that_v2_password_reproducible(ready, v2_state, cli, tmp_path):
    pykeepass = pytest.importorskip("pykeepass")
    out = tmp_path / "pairs.kdbx"
    cli(["--migrate-v2", "--keep-v2-files", "--export-kdbx", str(out)],
        secrets=[V2_MASTER, "2026/01", MASTER, BOOST, ACCESS, "k", "k"])
    database = pykeepass.PyKeePass(str(out), password="k")
    assert database.find_entries(title="com-temporal (v2)", first=True).password == v2_state["com-temporal"]
    assert database.find_entries(title="github.com (v2)", first=True) is None   # made without that secret


def test_v2_show_is_read_only(ready, v2_state, cli, isolated_home):
    def snapshot():
        root = isolated_home / ".passweird"
        return {p: open(p, "rb").read() for d, _, names in os.walk(root) for p in (os.path.join(d, n) for n in names)}
    before = snapshot()
    assert cli(["--v2-show", "ufpb-sigaa"], secrets=[V2_MASTER, ""]).value("v2 password:") == v2_state["ufpb-sigaa"]
    assert cli(["--v2-show", "github.com", "-L", "24", "-s"], secrets=[V2_MASTER, ""]).value("v2 password:") == \
        v2_state["github.com"]
    assert cli(["--v2-show", "com-temporal"], secrets=[V2_MASTER, "2026/01"]).value("v2 password:") == \
        v2_state["com-temporal"]
    assert snapshot() == before


def test_v2_keyfile_is_used_for_reading(ready, cli, isolated_home, tmp_path):
    keyfile = tmp_path / "v2.key"
    crypto.generate_random_keyfile(crypto.modified_hash(V2_MASTER), str(keyfile))
    blended = crypto.modified_hash(V2_MASTER, keyfile_path=str(keyfile))
    source = tmp_path / "hosts.txt"
    source.write_text("so-com-keyfile.example\n", encoding="utf-8")
    storage.encrypt_and_save_hosts(blended, str(source))
    assert cli(["--migrate-v2", "--keep-v2-files"], secrets=[V2_MASTER, ACCESS]).code == 1
    result = cli(["--migrate-v2", "--keep-v2-files", "--v2-key-file", str(keyfile)], secrets=[V2_MASTER, ACCESS])
    assert result.code == 0 and "Sites imported: 1" in result.out


def test_plan_is_pure_and_maps_the_v2_flags():
    assert migrate.classes_from_feat("1111") == 15 and migrate.classes_from_feat("0010") == 4
    assert migrate.classes_from_feat("0000") is None and migrate.classes_from_feat("11") is None
    summary = crypto.summarize_hash(crypto.modified_hash("a.example"))
    items, rejected = migrate.plan(["a.example", "b c"], {summary: {"length": "007", "feat": "1111",
                                                                   "temporal": "", "date": "20260101000000"}})
    assert rejected and rejected[0][0] == "b c"
    assert items[0]["length"] is None and "outside the v3 range" in items[0]["notes"][0]
    assert items[0]["v2_length"] == 7
