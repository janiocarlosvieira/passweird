# ADR-0009 §12 - the command line, end to end.
import hashlib
import io
import os
import re
import stat
import sys

import pytest

from passweird import main
from passweird.v3 import app, derive, journal, keys

MASTER, BOOST, ACCESS, USER = "minha mestra", "cavalo bateria grampo correto girassol", "abre o diario", "fulano@example.com"
SECRETS = [MASTER, BOOST, ACCESS]


@pytest.fixture
def fast(monkeypatch):
    """Cheap stand-ins for the two Argon2id runs. The real ones are exercised
    in test_v3_derive.py, test_v3_journal.py and the 'real' test below."""
    def fake_stretch(master, boost, user_id):
        return bytearray(hashlib.sha512(derive.stretch_input(master, boost) + derive.salt_for(user_id)).digest())
    monkeypatch.setattr(derive, "stretch", fake_stretch)
    monkeypatch.setattr(keys, "DEFAULT_ACCESS_PARAMS", (1024, 1, 1))


@pytest.fixture
def cli(monkeypatch, capsys):
    def run(argv, secrets=(), inputs=(), stdin=None):
        asked = []
        secret_iter, input_iter = iter(secrets), iter(inputs)

        def fake_getpass(prompt=""):
            asked.append(prompt)
            return next(secret_iter)

        monkeypatch.setattr("getpass.getpass", fake_getpass)
        monkeypatch.setattr("builtins.input", lambda prompt="": next(input_iter))
        if stdin is not None:
            monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        monkeypatch.setattr(sys, "argv", ["passweird"] + list(argv))
        with pytest.raises(SystemExit) as exc:
            main.main()
        captured = capsys.readouterr()
        return Result(exc.value.code, captured.out, captured.err, asked)
    return run


class Result:
    def __init__(self, code, out, err, asked):
        self.code, self.out, self.err, self.asked = code, out, err, asked

    def value(self, label):
        match = re.search(rf"^{re.escape(label)}\s*(.+)$", self.out, re.MULTILINE)
        assert match, f"{label!r} not in output:\n{self.out}\n{self.err}"
        return match.group(1).strip()

    @property
    def password(self):
        return self.value("Password:")

    @property
    def recovery_text(self):
        lines = [l for l in self.out.splitlines() if re.fullmatch(r"[A-Z2-7]{4}( [A-Z2-7]{1,4})*", l)]
        assert lines, self.out
        return " ".join(lines)


@pytest.fixture
def ready(fast, cli):
    """An initialised installation."""
    result = cli(["--init", "--user-id", USER], secrets=[MASTER, MASTER, BOOST, BOOST, ACCESS, ACCESS])
    assert result.code == 0, result.err
    return result


def _files(root):
    for directory, _, names in os.walk(root):
        for name in names:
            yield os.path.join(directory, name)


# --- setup -------------------------------------------------------------------

def test_gen_boost(cli):
    result = cli(["--gen-boost"])
    assert result.code == 0 and len(result.value("Boost:").split()) == 5 and "64.6 bits" in result.out
    assert len(cli(["--gen-boost", "4"]).value("Boost:").split()) == 4
    assert cli(["--gen-boost", "3"]).code == 1


def test_init_creates_the_tiers_and_stores_no_recovery(ready, isolated_home):
    base = isolated_home / ".passweird" / "v3"
    assert sorted(os.listdir(base)) == ["config", "journal"]
    assert sorted(os.listdir(base / "journal")) == ["keys.pw3", "streams"]
    assert re.fullmatch(r"[a-z]{4}-[a-z]{4}", ready.value("Fingerprint:"))
    blob = keys.recovery_from_text(ready.recovery_text)
    assert blob[:4] == keys.MAGIC_RECOVERY
    assert "shown ONCE" in ready.out


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_everything_written_is_private(ready, cli, isolated_home):
    cli(["github.com"], secrets=SECRETS)
    root = isolated_home / ".passweird"
    for directory, _, names in os.walk(root):
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700, directory
        for name in names:
            assert stat.S_IMODE(os.stat(os.path.join(directory, name)).st_mode) == 0o600, name


def test_init_with_keep_recovery_file(fast, cli, isolated_home):
    result = cli(["--init", "--user-id", USER, "--keep-recovery-file"],
                 secrets=[MASTER, MASTER, BOOST, BOOST, ACCESS, ACCESS])
    assert result.code == 0
    stored = (isolated_home / ".passweird" / "v3" / "recovery.pw3").read_bytes()
    assert stored == keys.recovery_from_text(result.recovery_text)
    # With the file, a derivation asks for master and boost only.
    derived = cli(["github.com"], secrets=[MASTER, BOOST])
    assert derived.code == 0 and len(derived.asked) == 2
    wrong = cli(["github.com"], secrets=[MASTER + "x", BOOST])
    assert wrong.code == 1 and "typo" in wrong.err and "Password:" not in wrong.out


@pytest.mark.parametrize("secrets, message", [
    ([MASTER, MASTER + "x"], "do not match"),
    ([MASTER, MASTER, BOOST, BOOST, MASTER, MASTER], "must differ"),
    ([MASTER, MASTER, BOOST, BOOST, BOOST.upper(), BOOST.upper()], "do not match|must differ"),
    (["", ""], "must not be empty"),
])
def test_init_refuses_bad_secrets(fast, cli, isolated_home, secrets, message):
    result = cli(["--init", "--user-id", USER], secrets=secrets)
    assert result.code == 1 and re.search(message, result.err)
    assert not (isolated_home / ".passweird" / "v3" / "config").exists()


def test_access_password_may_not_equal_the_boost(fast, cli):
    result = cli(["--init", "--user-id", USER], secrets=[MASTER, MASTER, BOOST, BOOST, BOOST, BOOST])
    assert result.code == 1 and "must differ" in result.err


def test_init_twice_is_refused(ready, cli):
    assert cli(["--init", "--user-id", USER], secrets=[MASTER] * 6).code == 1


def test_secrets_are_not_accepted_as_arguments(cli):
    for flag in ("--master-pass", "--master-file", "-T", "--temporal", "--register-master", "--fido2", "-o"):
        result = cli([flag, "x", "github.com"])
        assert result.code == 2, flag


# --- derivation --------------------------------------------------------------

def test_site_and_fingerprint_come_before_the_password(ready, cli):
    result = cli(["https://WWW.GitHub.com/login"], secrets=SECRETS)
    assert result.code == 0
    out = result.out
    assert out.index("Site: github.com") < out.index("Fingerprint:") < out.index("Password:")
    assert result.value("Fingerprint:") == ready.value("Fingerprint:")
    assert "Journal updated." in out


def test_same_inputs_same_password_and_no_second_record(ready, cli):
    first = cli(["github.com"], secrets=SECRETS)
    second = cli(["GITHUB.com."], secrets=SECRETS)
    assert first.password == second.password and len(first.password) == 18
    assert "Journal updated." not in second.out


def test_login_site_counter_and_secrets_all_change_the_password(ready, cli):
    seen = {
        cli(["github.com"], secrets=SECRETS).password,
        cli(["github.com", "-u", "fulano"], secrets=SECRETS).password,
        cli(["gitlab.com"], secrets=SECRETS).password,
        cli(["github.com", "--no-journal"], secrets=[MASTER + "x", BOOST]).password,
        cli(["github.com", "--no-journal"], secrets=[MASTER, BOOST + " x"]).password,
        cli(["github.com", "--no-journal", "-C", "2"], secrets=[MASTER, BOOST]).password,
        cli(["github.com", "--no-journal", "--user-id", "outra@example.com"], secrets=[MASTER, BOOST]).password,
    }
    assert len(seen) == 7


def test_boost_typed_on_a_phone_keyboard_is_the_same_boost(ready, cli):
    a = cli(["github.com", "--no-journal"], secrets=[MASTER, BOOST])
    b = cli(["github.com", "--no-journal"], secrets=[MASTER, "  Cavalo  Bateria grampo correto GIRASSOL "])
    assert a.password == b.password


def test_stateless_run_matches_the_journaled_one_and_writes_nothing(ready, cli, isolated_home):
    journaled = cli(["github.com"], secrets=SECRETS)
    before = {p: open(p, "rb").read() for p in _files(isolated_home)}
    stateless = cli(["github.com", "--no-journal"], secrets=[MASTER, BOOST])
    assert stateless.password == journaled.password and len(stateless.asked) == 2
    assert {p: open(p, "rb").read() for p in _files(isolated_home)} == before


def test_stateless_without_any_configuration(fast, cli, isolated_home):
    assert cli(["github.com"], secrets=[MASTER, BOOST]).code == 1
    assert cli(["github.com", "--no-journal"], secrets=[MASTER, BOOST]).code == 1
    result = cli(["github.com", "--no-journal", "--user-id", USER], secrets=[MASTER, BOOST])
    assert result.code == 0 and result.password
    assert not (isolated_home / ".passweird").exists()


def test_journal_entry_wins_over_flags_unless_forced(ready, cli):
    original = cli(["github.com"], secrets=SECRETS).password
    refused = cli(["github.com", "-L", "24"], secrets=SECRETS)
    assert refused.code == 1 and "--force" in refused.err and "Password:" not in refused.out
    refused = cli(["github.com", "-s"], secrets=SECRETS)
    assert refused.code == 1
    forced = cli(["github.com", "-L", "24", "-s", "--force"], secrets=SECRETS)
    assert len(forced.password) == 24 and forced.password.isalnum()
    remembered = cli(["github.com"], secrets=SECRETS)
    assert remembered.password == forced.password != original


def test_new_entry_takes_the_flags(ready, cli):
    first = cli(["pin.example", "-L", "6", "-U", "-l", "-s"], secrets=SECRETS)
    assert first.password.isdigit() and len(first.password) == 6
    assert cli(["pin.example"], secrets=SECRETS).password == first.password


def test_bump_shows_both_passwords_and_records_the_new_counter(ready, cli):
    old = cli(["github.com"], secrets=SECRETS).password
    bumped = cli(["github.com", "--bump"], secrets=SECRETS)
    assert bumped.value("Current password (counter 1):") == old
    new = bumped.value("New password     (counter 2):")
    assert new != old
    after = cli(["github.com"], secrets=SECRETS)
    assert after.password == new and "Counter: 2" in after.out
    # An earlier counter can still be derived, and does not move the journal back.
    earlier = cli(["github.com", "-C", "1"], secrets=SECRETS)
    assert earlier.password == old and "Journal updated." not in earlier.out
    assert cli(["github.com"], secrets=SECRETS).password == new
    assert cli(["github.com", "--bump", "-C", "5"], secrets=SECRETS).code == 1


@pytest.mark.parametrize("argv", [["bücher.de"], ["minha conta"], ["github.com", "-L", "7"],
                                  ["github.com", "-U", "-l", "-n", "-s"], ["github.com", "-C", "0"]])
def test_invalid_inputs_are_rejected_before_any_password(ready, cli, argv):
    result = cli(argv, secrets=SECRETS)
    assert result.code == 1 and "Password:" not in result.out and result.err.startswith("Error:")


def test_non_ascii_site_points_to_the_xn_form(ready, cli):
    assert "xn--" in cli(["bücher.de"], secrets=SECRETS).err
    assert cli(["xn--bcher-kva.de"], secrets=SECRETS).code == 0


def test_wrong_access_password_gives_no_password(ready, cli):
    result = cli(["github.com"], secrets=[MASTER, BOOST, "errada"])
    assert result.code == 1 and "wrong access password" in result.err and "Password:" not in result.out


def test_paranoid_mode_hides_the_site(ready, cli):
    shown = cli(["github.com"], secrets=SECRETS).password
    hidden = cli(["-p"], secrets=["github.com"] + SECRETS)
    assert hidden.password == shown and "github.com" not in hidden.out


def test_totp(ready, cli):
    result = cli(["github.com", "--totp"], secrets=SECRETS)
    secret = result.value("TOTP secret (Base32):")
    assert re.fullmatch(r"[A-Z2-7]{32}", secret) and "Password:" not in result.out
    assert cli(["github.com", "--totp"], secrets=SECRETS).value("TOTP secret (Base32):") == secret


def test_secrets_stdin(ready, cli):
    interactive = cli(["github.com"], secrets=SECRETS)
    piped = cli(["github.com", "--secrets-stdin"], stdin="\n".join(SECRETS) + "\n")
    assert piped.password == interactive.password and piped.asked == []
    short = cli(["github.com", "--secrets-stdin"], stdin=MASTER + "\n")
    assert short.code == 1 and "no more input" in short.err


# --- nothing on disk can generate --------------------------------------------

def test_no_secret_or_password_reaches_the_disk(ready, cli, isolated_home):
    password = cli(["github.com", "-u", "fulano"], secrets=SECRETS).password
    cli(["github.com", "-u", "fulano", "--bump"], secrets=SECRETS)
    session = derive.Session.open(MASTER, BOOST, USER)
    forbidden = [MASTER.encode(), BOOST.encode(), ACCESS.encode(), password.encode(),
                 bytes(session._k0), bytes(session.prk_none),
                 bytes(session.prk_none).hex().encode(), session.fingerprint.encode()]
    names = []
    for path in _files(isolated_home):
        data = open(path, "rb").read()
        names.append(os.path.basename(path))
        for needle in forbidden:
            assert needle not in data, f"{path} contains secret material"
    assert "master.hash" not in names and not any(n.endswith((".csv", ".log")) for n in names)
    # The site name is not readable either: the stream is encrypted.
    assert all(b"github" not in open(p, "rb").read() for p in _files(isolated_home / ".passweird" / "v3" / "journal"))


def test_output_carries_no_hash_summary_of_the_secrets(ready, cli):
    out = cli(["github.com"], secrets=SECRETS).out
    assert MASTER not in out and BOOST not in out and ACCESS not in out
    assert not re.search(r"\b(master|temporal|pwd):[0-9a-f]", out)


# --- journal tier: access password only --------------------------------------

def test_consulting_the_journal_needs_only_the_access_password(ready, cli):
    cli(["github.com", "-u", "fulano"], secrets=SECRETS)
    cli(["example.org"], secrets=SECRETS)
    listing = cli(["--list"], secrets=[ACCESS])
    assert listing.code == 0 and len(listing.asked) == 1 and "Access password" in listing.asked[0]
    assert "github.com  (fulano)" in listing.out and "example.org" in listing.out
    assert "Password" not in listing.out and "Fingerprint" not in listing.out
    assert cli(["--list"], secrets=["errada"]).code == 1
    assert cli(["--list"], secrets=[MASTER]).code == 1          # the master does not open the journal


def test_edit_show_history_delete(ready, cli):
    cli(["github.com"], secrets=SECRETS)
    edited = cli(["--edit", "github.com", "--notes", "conta pessoal", "--second-factor", "Aegis no celular",
                  "--hw-key", "YubiKey azul", "--hw-key", "reserva no cofre"], secrets=[ACCESS])
    assert edited.code == 0
    shown = cli(["--show", "github.com"], secrets=[ACCESS]).out
    for text in ("conta pessoal", "Aegis no celular", "YubiKey azul, reserva no cofre", "Counter: 1"):
        assert text in shown
    # Free-form fields never change the derivation.
    assert "Journal updated." not in cli(["github.com"], secrets=SECRETS).out
    history = cli(["--history", "github.com"], secrets=[ACCESS]).out
    assert history.count(" put ") == 2
    assert cli(["--delete", "github.com"], secrets=[ACCESS]).code == 0
    assert "github.com" not in cli(["--list"], secrets=[ACCESS]).out
    assert cli(["--show", "github.com"], secrets=[ACCESS]).code == 1


def test_a_deleted_site_resumes_from_its_counter(ready, cli):
    cli(["github.com"], secrets=SECRETS)
    bumped = cli(["github.com", "--bump"], secrets=SECRETS).value("New password     (counter 2):")
    cli(["--delete", "github.com"], secrets=[ACCESS])
    again = cli(["github.com"], secrets=SECRETS)
    assert "Counter: 2" in again.out and again.password == bumped


def test_import_list(ready, cli, tmp_path):
    source = tmp_path / "sites.txt"
    source.write_text("# meus sites\nGitHub.com fulano\nhttps://www.example.org/login\n\nbücher.de\nexample.org\n",
                      encoding="utf-8")
    result = cli(["--import-list", str(source)], secrets=[ACCESS])
    assert "Imported 2, already present 1, rejected 1." in result.out and "line 5" in result.out
    listing = cli(["--list"], secrets=[ACCESS]).out
    assert "github.com  (fulano)" in listing and "example.org" in listing


def test_change_access_password_and_its_limit(ready, cli, isolated_home):
    keys_file = isolated_home / ".passweird" / "v3" / "journal" / "keys.pw3"
    old_copy = keys_file.read_bytes()
    result = cli(["--change-access-password"], secrets=[ACCESS, "nova senha", "nova senha"])
    assert result.code == 0 and "does not revoke" in result.out
    assert cli(["--list"], secrets=["nova senha"]).code == 0
    assert cli(["--list"], secrets=[ACCESS]).code == 1
    # The documented limit: an old copy of keys.pw3 still opens the journal.
    assert keys.open_keys_file(old_copy, ACCESS)[1] == keys.open_keys_file(keys_file.read_bytes(), "nova senha")[1]
    assert cli(["--change-access-password"], secrets=["errada", "a", "a"]).code == 1


def test_recover_with_the_printed_text(ready, cli, isolated_home):
    cli(["github.com"], secrets=SECRETS)
    text = ready.recovery_text
    wrong = cli(["--recover"], secrets=[MASTER + "x", BOOST, "nova", "nova"], inputs=[text, ""])
    assert wrong.code == 1
    result = cli(["--recover"], secrets=[MASTER, BOOST, "nova senha", "nova senha"], inputs=[text.lower(), ""])
    assert result.code == 0, result.err
    assert "github.com" in cli(["--list"], secrets=["nova senha"]).out
    assert not (isolated_home / ".passweird" / "v3" / "recovery.pw3").exists()


def test_recover_from_a_file_and_print_recovery(ready, cli, tmp_path):
    again = cli(["--print-recovery"], secrets=SECRETS)
    assert again.code == 0
    path = tmp_path / "recovery.txt"
    path.write_text(again.recovery_text, encoding="utf-8")
    assert cli(["--recover", "--recovery-file", str(path)], secrets=[MASTER, BOOST, "nova", "nova"]).code == 0
    assert cli(["--list"], secrets=["nova"]).code == 0


# --- several devices ---------------------------------------------------------

@pytest.fixture
def devices(fast, cli, tmp_path, monkeypatch):
    """Two homes sharing one journal folder, as a sync tool would arrange."""
    shared = tmp_path / "synced-journal"
    homes = {name: tmp_path / name for name in ("a", "b")}

    def on(name):
        homes[name].mkdir(exist_ok=True)
        for var in ("HOME", "USERPROFILE"):
            monkeypatch.setenv(var, str(homes[name]))
        drive, tail = os.path.splitdrive(str(homes[name]))
        monkeypatch.setenv("HOMEDRIVE", drive)
        monkeypatch.setenv("HOMEPATH", tail)

    on("a")
    assert cli(["--init", "--user-id", USER, "--journal-dir", str(shared)],
               secrets=[MASTER, MASTER, BOOST, BOOST, ACCESS, ACCESS]).code == 0
    on("b")
    assert cli(["--join", "--user-id", USER, "--journal-dir", str(shared)], secrets=[ACCESS]).code == 0
    return on, shared


def test_join_and_see_the_other_device(devices, cli):
    on, shared = devices
    on("a")
    password = cli(["github.com"], secrets=SECRETS).password
    on("b")
    result = cli(["github.com"], secrets=SECRETS)
    assert result.password == password and "Journal updated." not in result.out
    assert len(os.listdir(shared / "streams")) == 1          # B has written nothing yet
    cli(["example.org"], secrets=SECRETS)
    assert len(os.listdir(shared / "streams")) == 2


def test_join_checks_the_access_password(fast, cli, tmp_path, ready):
    assert cli(["--join"], secrets=[ACCESS]).code == 1        # already initialised here


def test_divergent_bumps_are_flagged_then_resolved(devices, cli, tmp_path, monkeypatch):
    on, shared = devices
    on("a")
    cli(["github.com"], secrets=SECRETS)
    stream_a = next(p for p in (shared / "streams").iterdir())
    snapshot = stream_a.read_bytes()

    cli(["github.com", "--bump"], secrets=SECRETS)
    cli(["github.com", "--bump"], secrets=SECRETS)            # A is at counter 3
    advanced = stream_a.read_bytes()

    # B bumps without having seen A's bumps: put A's stream back to the snapshot
    # for B's run (its 'seen' file has never recorded more than that).
    on("b")
    stream_a.write_bytes(snapshot)
    cli(["github.com", "--bump"], secrets=SECRETS)            # B is at counter 2
    stream_a.write_bytes(advanced)                            # sync catches up

    listing = cli(["--list"], secrets=[ACCESS]).out
    assert "counter 3" in listing and "[CONFLICT]" in listing
    derived = cli(["github.com"], secrets=SECRETS)
    assert "WARNING" in derived.out and "Counter: 3" in derived.out
    assert cli(["--resolve", "github.com"], secrets=[ACCESS]).code == 0
    on("a")
    assert "[CONFLICT]" not in cli(["--list"], secrets=[ACCESS]).out


def test_new_device_id(devices, cli):
    on, shared = devices
    on("b")
    cli(["example.org"], secrets=SECRETS)
    assert cli(["--new-device-id"]).code == 0
    cli(["other.example"], secrets=SECRETS)
    assert len(os.listdir(shared / "streams")) == 2           # A has none; B has old and new
    assert "example.org" in cli(["--list"], secrets=[ACCESS]).out


# --- keyfile -----------------------------------------------------------------

def test_keyfile_factor(ready, cli, tmp_path):
    path = tmp_path / "factor.pw3f"
    assert cli(["--gen-keyfile", str(path)], secrets=[MASTER, BOOST]).code == 0
    assert path.read_bytes()[:4] == keys.MAGIC_KEYFILE
    assert cli(["--gen-keyfile", str(path)], secrets=[MASTER, BOOST]).code == 1      # never overwrites
    plain = cli(["github.com", "--no-journal"], secrets=[MASTER, BOOST])
    with_key = cli(["github.com", "--no-journal", "--key-file", str(path)], secrets=[MASTER, BOOST])
    assert with_key.password != plain.password
    assert with_key.value("Fingerprint:") == plain.value("Fingerprint:")
    assert cli(["github.com", "--no-journal", "--key-file", str(path)], secrets=[MASTER, BOOST]).password == \
        with_key.password
    wrong = cli(["github.com", "--no-journal", "--key-file", str(path)], secrets=[MASTER + "x", BOOST])
    assert wrong.code == 1 and "Password:" not in wrong.out
    assert cli(["github.com", "--no-journal", "--key-file", str(tmp_path / "nope")], secrets=[MASTER, BOOST]).code == 1


# --- export ------------------------------------------------------------------

def test_export_kdbx(ready, cli, tmp_path):
    pykeepass = pytest.importorskip("pykeepass")
    github = cli(["github.com", "-u", "fulano"], secrets=SECRETS).password
    example = cli(["example.org"], secrets=SECRETS).password
    cli(["--edit", "github.com", "-u", "fulano", "--notes", "pessoal"], secrets=[ACCESS])
    out = tmp_path / "export.kdbx"
    result = cli(["--export-kdbx", str(out)], secrets=SECRETS + ["senha kdbx", "senha kdbx"])
    assert result.code == 0, result.err
    assert "Merge From" in result.out and "Argon2id, 256 MiB" in result.out
    database = pykeepass.PyKeePass(str(out), password="senha kdbx")
    entry = database.find_entries(title="github.com", first=True)
    assert (entry.username, entry.password, entry.notes) == ("fulano", github, "pessoal")
    assert entry.get_custom_property("passweird_counter") == "1"
    assert database.find_entries(title="example.org", first=True).password == example
    assert github not in result.out
    again = cli(["--export-kdbx", str(out)], secrets=SECRETS + ["x", "x"])
    assert again.code == 1 and "overwrite" in again.err
    one = tmp_path / "one.kdbx"
    assert cli(["example.org", "--export-kdbx", str(one)], secrets=SECRETS + ["x", "x"]).code == 0
    assert len(pykeepass.PyKeePass(str(one), password="x").entries) == 1


def test_mass_rekey(ready, cli, tmp_path):
    pykeepass = pytest.importorskip("pykeepass")
    old = cli(["github.com"], secrets=SECRETS).password
    out = tmp_path / "rekey.kdbx"
    new_master, new_boost = "outra mestra", "novo reforco de cinco palavras aqui"
    result = cli(["--mass-rekey", "--export-kdbx", str(out)],
                 secrets=[MASTER, BOOST, ACCESS, new_master, new_master, new_boost, new_boost, "k", "k"])
    assert result.code == 0, result.err
    database = pykeepass.PyKeePass(str(out), password="k")
    assert database.find_entries(title="github.com (old)", first=True).password == old
    new = database.find_entries(title="github.com (new)", first=True).password
    assert cli(["github.com"], secrets=[new_master, new_boost, ACCESS]).password == new != old
    assert result.value("New fingerprint:") != ready.value("Fingerprint:")
    assert cli(["--mass-rekey"], secrets=SECRETS).code == 1


# --- one run with the real KDFs ----------------------------------------------

def test_real_argon2_end_to_end(cli):
    assert cli(["--init", "--user-id", USER], secrets=[MASTER, MASTER, BOOST, BOOST, ACCESS, ACCESS]).code == 0
    result = cli(["github.com", "-u", "Fulano"], secrets=SECRETS)
    with derive.Session.open(MASTER, BOOST, USER) as session:
        assert result.password == session.password("github.com", "fulano")
        assert result.value("Fingerprint:") == session.fingerprint


# --- key material ------------------------------------------------------------

def test_ssh_and_ssl_from_the_cli_are_reproducible_and_recorded(ready, cli):
    first = cli(["host.example", "--ssh"], secrets=SECRETS)
    assert first.code == 0 and "ssh-ed25519 " in first.out and "BEGIN OPENSSH PRIVATE KEY" in first.out
    assert "Journal updated." in first.out and "Password:" not in first.out
    second = cli(["host.example", "--ssh"], secrets=SECRETS)
    assert second.out.split("[SSH public key]")[1] == first.out.split("[SSH public key]")[1].replace(
        "Journal updated.\n", "")
    rotated = cli(["host.example", "--ssh", "-C", "2"], secrets=SECRETS)
    assert rotated.out.split("[SSH public key]")[1].split("\n")[1] != first.out.split("[SSH public key]")[1].split("\n")[1]
    cert = cli(["host.example", "--ssl"], secrets=SECRETS)
    assert "BEGIN CERTIFICATE" in cert.out and "BEGIN PRIVATE KEY" in cert.out
    assert cli(["host.example", "--ssh", "--bump"], secrets=SECRETS).code == 1


def test_bad_rsa_size_fails_before_any_prompt(ready, cli):
    result = cli(["host.example", "--rsa", "1024"], secrets=SECRETS)
    assert result.code == 2 and result.asked == []
