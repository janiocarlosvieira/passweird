# ADR-0013 - profiles: several independent installations on one device.
import hashlib
import json
import os
import shutil
import stat
import sys

import pytest

from passweird.v3 import app, derive, keys, profiles
from test_v3_cli import ACCESS, BOOST, MASTER, SECRETS, USER, _files
from test_v3_cli import cli, devices, fast, ready  # noqa: F401  (fixtures)
from v3_support import load

MASTER2, BOOST2, ACCESS2, USER2 = ("mestra do trabalho", "mesa cadeira janela porta tapete",
                                   "abre o trabalho", "fulano@empresa.example")
SECRETS2 = [MASTER2, BOOST2, ACCESS2]
INIT = [MASTER, MASTER, BOOST, BOOST, ACCESS, ACCESS]
INIT2 = [MASTER2, MASTER2, BOOST2, BOOST2, ACCESS2, ACCESS2]
NEW_ACCESS = "nova senha de acesso"
WORK = ["--profile", "work"]


def base(home):
    return home / ".passweird" / "v3"


def profile_dir(home, name):
    return base(home) / "profiles" / name


def config_of(home, name="default"):
    directory = base(home) if name == "default" else profile_dir(home, name)
    return json.loads((directory / "config").read_text(encoding="utf-8"))


def snapshot(root, skip=None):
    return {p: hashlib.sha256(open(p, "rb").read()).hexdigest()
            for p in _files(root) if not (skip and p.startswith(str(skip)))}


def point_journal(home, name, folder):
    """Hand-edits a profile's config so that it names another journal folder."""
    directory = base(home) if name == "default" else profile_dir(home, name)
    config = config_of(home, name)
    config["journal_dir"] = str(folder)
    (directory / "config").write_text(json.dumps(config), encoding="utf-8")


def go_home(monkeypatch, home):
    home.mkdir(exist_ok=True)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    drive, tail = os.path.splitdrive(str(home))
    monkeypatch.setenv("HOMEDRIVE", drive)
    monkeypatch.setenv("HOMEPATH", tail)


@pytest.fixture
def work(fast, cli):
    """A named profile with its own secrets, user id and journal."""
    result = cli(WORK + ["--init", "--user-id", USER2], secrets=INIT2)
    assert result.code == 0, result.err
    return result


@pytest.fixture
def stretches(fast, monkeypatch):
    """Records every Argon2id stretch, to prove a check ran before it."""
    calls, inner = [], derive.stretch

    def spy(*args):
        calls.append(args)
        return inner(*args)
    monkeypatch.setattr(derive, "stretch", spy)
    return calls


# --- names -------------------------------------------------------------------

@pytest.mark.parametrize("raw, name", [
    ("work", "work"), ("  Work\t", "work"), ("WORK-2", "work-2"), ("a", "a"), ("7", "7"),
    ("a" * 32, "a" * 32), ("x-y-z", "x-y-z"), ("a--b", "a--b"),
    ("com0", "com0"), ("com10", "com10"), ("lpt", "lpt"), ("console", "console"), ("nul1", "nul1"),
    ("default", "default"), ("DEFAULT", "default"),
])
def test_accepted_names(raw, name):
    assert profiles.canonical_name(raw) == name


@pytest.mark.parametrize("raw", [
    "", "   ", "-work", "work-", "-", "a" * 33, "wo rk", "wo_rk", "wo.rk", "../work", "wo/rk", "wo\\rk",
    "wo\nrk", "ação", "worK", "ｗork", "work!",
])
def test_rejected_names_state_the_rule(raw):
    with pytest.raises(profiles.ProfileError) as exc:
        profiles.canonical_name(raw)
    assert "a-z" in str(exc.value) and "32" in str(exc.value)


@pytest.mark.parametrize("raw", ["con", "prn", "aux", "nul", "CON", " Nul "]
                         + [f"com{i}" for i in range(1, 10)] + [f"LPT{i}" for i in range(1, 10)])
def test_windows_device_names_are_refused_everywhere(raw):
    with pytest.raises(profiles.ProfileError) as exc:
        profiles.canonical_name(raw)
    assert "reserved" in str(exc.value)


# --- selection ---------------------------------------------------------------

def test_selection_order():
    env = profiles.ENV_VAR
    assert profiles.resolve(None, {}).name == "default"
    assert profiles.resolve(None, {env: ""}).name == "default"
    assert profiles.resolve(None, {env: "Work"}).name == "work"
    assert profiles.resolve("home", {env: "work"}).name == "home"
    assert profiles.resolve("default", {env: "work"}).name == "default"
    for cli_value, environ in (("", {}), ("con", {}), (None, {env: "a_b"})):
        with pytest.raises(profiles.ProfileError):
            profiles.resolve(cli_value, environ)


def test_paths_of_default_and_named_profiles(isolated_home):
    default = profiles.resolve(None, {})
    assert default.is_default and default.directory == str(base(isolated_home))
    assert default.config_path == str(base(isolated_home) / "config")
    assert default.recovery_path == str(base(isolated_home) / "recovery.pw3")
    assert default.default_journal_dir == str(base(isolated_home) / "journal")
    named = profiles.resolve("work", {})
    assert not named.is_default and named.directory == str(profile_dir(isolated_home, "work"))
    assert named.config_path == str(profile_dir(isolated_home, "work") / "config")
    assert named.recovery_path == str(profile_dir(isolated_home, "work") / "recovery.pw3")
    assert named.default_journal_dir == str(profile_dir(isolated_home, "work") / "journal")
    with pytest.raises(Exception):
        named.name = "other"                      # frozen


def test_flag_over_environment_over_default(ready, work, cli, monkeypatch):
    cli(["github.com"], secrets=SECRETS)
    cli(WORK + ["gitlab.com"], secrets=SECRETS2)
    monkeypatch.setenv(profiles.ENV_VAR, "work")
    from_env = cli(["--list"], secrets=[ACCESS2])
    assert from_env.code == 0 and from_env.out.startswith("Profile: work\n")
    assert "gitlab.com" in from_env.out and "github.com" not in from_env.out
    flag = cli(["--profile", "default", "--list"], secrets=[ACCESS])
    assert flag.code == 0 and "Profile:" not in flag.out
    assert "github.com" in flag.out and "gitlab.com" not in flag.out
    monkeypatch.setenv(profiles.ENV_VAR, "")
    assert "github.com" in cli(["--list"], secrets=[ACCESS]).out


@pytest.mark.parametrize("argv", [
    ["github.com"], ["github.com", "--no-journal", "--user-id", USER], ["--list"], ["--show", "x.example"],
    ["--new-device-id"], ["--gen-keyfile", "k.pw3f", "--user-id", USER], ["--pin-key-file", "k.pw3f"],
    ["--unpin-key-file"], ["--print-recovery"], ["--recover"], ["--change-access-password"],
    ["--export-kdbx", "x.kdbx"], ["--migrate-v2"],
])
def test_unknown_profile_is_an_error_and_creates_nothing(ready, cli, isolated_home, argv, monkeypatch):
    monkeypatch.chdir(isolated_home)
    before = snapshot(isolated_home)
    result = cli(["--profile", "nope"] + argv, secrets=SECRETS)
    assert result.code == 1 and result.asked == [] and "Password:" not in result.out
    assert "'nope'" in result.err and "--init --profile nope" in result.err and "--join --profile nope" in result.err
    assert snapshot(isolated_home) == before
    assert not (base(isolated_home) / "profiles").exists()


def test_unknown_profile_from_the_environment_on_a_fresh_device(fast, cli, isolated_home, monkeypatch):
    monkeypatch.setenv(profiles.ENV_VAR, "nope")
    result = cli(["github.com", "--no-journal", "--user-id", USER], secrets=[MASTER, BOOST])
    assert result.code == 1 and "'nope'" in result.err and result.asked == []
    assert not (isolated_home / ".passweird").exists()


def test_invalid_name_is_an_error(fast, cli, isolated_home, monkeypatch):
    assert cli(["--profile", "Con", "github.com"], secrets=SECRETS).code == 1
    monkeypatch.setenv(profiles.ENV_VAR, "my_work")
    result = cli(["--init", "--user-id", USER], secrets=INIT)
    assert result.code == 1 and "a-z" in result.err and result.asked == []
    assert not (isolated_home / ".passweird").exists()


def test_gen_boost_and_list_profiles_need_no_existing_profile(fast, cli, isolated_home):
    boost = cli(["--profile", "nope", "--gen-boost"])
    assert boost.code == 0 and "Profile:" not in boost.out and boost.value("Boost:")
    listing = cli(["--profile", "nope", "--list-profiles"])
    assert listing.code == 0 and "Profile:" not in listing.out and "No profile" in listing.out
    assert not (isolated_home / ".passweird").exists()


# --- visibility --------------------------------------------------------------

def test_a_named_profile_shows_its_name_first_and_on_every_prompt(work, cli):
    assert work.out.startswith("Profile: work\n")
    assert work.asked and all(prompt.startswith("[work] ") for prompt in work.asked)
    result = cli(WORK + ["github.com"], secrets=SECRETS2)
    lines = result.out.splitlines()
    assert lines[0] == "Profile: work" and lines[1].startswith("Site: github.com")
    assert result.asked == ["[work] Master password: ", "[work] Boost: ", "[work] Access password: "]
    for argv, secrets in ((["--list"], [ACCESS2]), (["--new-device-id"], [])):
        assert cli(WORK + argv, secrets=secrets).out.startswith("Profile: work\n")


def test_text_prompts_carry_the_name_too(isolated_home, monkeypatch):
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt="": asked.append(prompt) or "x")
    app.Prompter(profile=profiles.resolve("work", {})).text("User id")
    app.Prompter(profile=profiles.resolve(None, {})).text("User id")
    app.Prompter().text("User id")
    assert asked == ["[work] User id: ", "User id: ", "User id: "]


def test_the_default_profile_output_is_unchanged(ready, cli):
    runs = [ready, cli(["github.com"], secrets=SECRETS), cli(["--list"], secrets=[ACCESS]),
            cli(["--profile", "default", "github.com"], secrets=SECRETS)]
    for result in runs:
        assert result.code == 0
        assert "Profile:" not in result.out and not any(p.startswith("[") for p in result.asked)
    assert runs[1].asked == ["Master password: ", "Boost: ", "Access password: "]


def test_list_profiles_and_gen_boost_print_no_profile_line(work, cli):
    assert "Profile:" not in cli(WORK + ["--list-profiles"]).out
    assert "Profile:" not in cli(WORK + ["--gen-boost"]).out


def test_list_profiles(ready, work, cli, isolated_home):
    (base(isolated_home) / "profiles" / "half-made").mkdir()        # no config: not listed
    result = cli(["--list-profiles"])
    assert result.code == 0 and result.asked == []
    headings = [line for line in result.out.splitlines() if line and not line.startswith(" ")]
    assert headings == ["default", "work"]
    default_block, work_block = result.out.split("\nwork\n")
    for block, home, user in ((default_block, base(isolated_home), USER),
                              (work_block, profile_dir(isolated_home, "work"), USER2)):
        config = config_of(isolated_home, "default" if home == base(isolated_home) else "work")
        assert f"User id: {user}" in block
        assert f"Journal folder: {home / 'journal'}" in block
        assert f"Device: {config['device_id'][:8]}" in block and config["device_id"][:9] not in block
        assert "Recovery file: not kept" in block and "Pinned keyfile: none" in block


def test_list_profiles_shows_kept_recovery_and_pinned_keyfile(fast, cli, tmp_path):
    keyfile = tmp_path / "k.pw3f"
    assert cli(["--gen-keyfile", str(keyfile), "--user-id", USER2], secrets=[MASTER2, BOOST2]).code == 0
    assert cli(WORK + ["--init", "--user-id", USER2, "--keep-recovery-file", "--key-file", str(keyfile)],
               secrets=INIT2).code == 0
    out = cli(["--list-profiles"]).out
    assert out.startswith("work\n") and "Recovery file: kept" in out and f"Pinned keyfile: {keyfile}" in out


def test_recovery_text_names_its_profile(ready, work, cli):
    for result, name, user in ((ready, "default", USER), (work, "work", USER2)):
        line = f'For profile "{name}", user id {user}'
        assert line in result.out
        first_group = result.recovery_text.split()[0]
        assert result.out.index(line) < result.out.index(first_group)
    again = cli(WORK + ["--print-recovery"], secrets=SECRETS2)
    assert f'For profile "work", user id {USER2}' in again.out


# --- default does not move ---------------------------------------------------

def test_default_keeps_todays_files(ready, cli, isolated_home):
    root = base(isolated_home)
    assert sorted(os.listdir(root)) == ["config", "journal"]
    config = config_of(isolated_home)
    assert config["journal_dir"] == str(root / "journal")
    assert "key_file" not in config and "key_file_sha256" not in config
    cli(["github.com"], secrets=SECRETS)
    cli(["--profile", "default", "--list"], secrets=[ACCESS])
    assert sorted(os.listdir(root)) == ["config", "journal", "seen"]


def test_named_profile_layout(work, isolated_home):
    home = profile_dir(isolated_home, "work")
    assert sorted(os.listdir(home)) == ["config", "journal"]
    assert sorted(os.listdir(home / "journal")) == ["keys.pw3", "streams"]
    assert config_of(isolated_home, "work")["journal_dir"] == str(home / "journal")
    assert sorted(os.listdir(base(isolated_home))) == ["profiles"]     # default is not initialised


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_named_profiles_are_private(work, cli, isolated_home):
    cli(WORK + ["github.com"], secrets=SECRETS2)
    for directory, _, names in os.walk(isolated_home / ".passweird"):
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700, directory
        for name in names:
            assert stat.S_IMODE(os.stat(os.path.join(directory, name)).st_mode) == 0o600, name


# --- profiles do not touch each other ----------------------------------------

def _exercise(cli, prefix, secrets, tmp_path):
    master, boost, access = secrets
    sites = tmp_path / f"sites-{len(prefix)}.txt"
    sites.write_text("example.org\nexample.net fulano\n", encoding="utf-8")
    keyfile = tmp_path / f"factor-{len(prefix)}.pw3f"
    steps = [
        (["github.com"], [master, boost, access]),
        (["github.com", "--bump"], [master, boost, access]),
        (["github.com", "--totp"], [master, boost, access]),
        (["github.com", "--no-journal"], [master, boost]),
        (["--edit", "github.com", "--notes", "pessoal"], [access]),
        (["--list"], [access]), (["--show", "github.com"], [access]), (["--history"], [access]),
        (["--resolve", "github.com"], [access]),
        (["--import-list", str(sites)], [access]),
        (["--change-access-password"], [access, "outra senha de acesso", "outra senha de acesso"]),
        (["--print-recovery", "--keep-recovery-file"], [master, boost, "outra senha de acesso"]),
        (["github.com"], [master, boost]),
        (["--gen-keyfile", str(keyfile)], [master, boost]),
        (["--pin-key-file", str(keyfile), "--force"], [master, boost]),
        (["github.com"], [master, boost]),
        (["--unpin-key-file"], []),
        (["--new-device-id"], []),
        (["--delete", "example.org"], ["outra senha de acesso"]),
        (["--list-profiles"], []),
    ]
    for argv, given in steps:
        result = cli(prefix + argv, secrets=given)
        assert result.code == 0, (argv, result.err)


@pytest.mark.parametrize("acting", ["work", "default"])
def test_operations_on_one_profile_leave_the_other_untouched(ready, work, cli, isolated_home, tmp_path, acting):
    cli(["github.com"], secrets=SECRETS)
    cli(WORK + ["github.com"], secrets=SECRETS2)
    profiles_root = base(isolated_home) / "profiles"
    if acting == "work":
        watched = lambda: snapshot(base(isolated_home), skip=profiles_root)       # noqa: E731
        prefix, secrets = WORK, SECRETS2
    else:
        watched = lambda: snapshot(profile_dir(isolated_home, "work"))           # noqa: E731
        prefix, secrets = [], SECRETS
    before = watched()
    assert before
    _exercise(cli, prefix, secrets, tmp_path)
    assert watched() == before


def test_profiles_separate_state_not_derivation(ready, cli):
    assert cli(WORK + ["--init", "--user-id", USER],
               secrets=[MASTER, MASTER, BOOST, BOOST, ACCESS2, ACCESS2]).code == 0
    a = cli(["github.com"], secrets=SECRETS)
    b = cli(WORK + ["github.com"], secrets=[MASTER, BOOST, ACCESS2])
    assert a.password == b.password and a.value("Fingerprint:") == b.value("Fingerprint:")
    c = cli(WORK + ["github.com", "--no-journal", "--user-id", USER2], secrets=[MASTER, BOOST])
    assert c.password != a.password


# --- independence checks (§6) ------------------------------------------------

def _attached_variants(tmp_path, shared):
    variants = [shared]
    if sys.platform != "win32":
        link = tmp_path / "link-to-journal"
        link.symlink_to(shared, target_is_directory=True)
        variants.append(link)
    copy = tmp_path / "copy-of-journal"
    shutil.copytree(shared, copy)
    variants.append(copy)
    return variants


def test_init_and_join_refuse_a_journal_of_another_profile(fast, cli, tmp_path, isolated_home):
    shared = tmp_path / "synced"
    assert cli(["--init", "--user-id", USER, "--journal-dir", str(shared)], secrets=INIT).code == 0
    for folder in _attached_variants(tmp_path, shared):
        join = cli(WORK + ["--join", "--user-id", USER, "--journal-dir", str(folder)],
                   secrets=[ACCESS], inputs=[""])
        assert join.code == 1 and "profile 'default'" in join.err and join.asked == [], folder
        init = cli(WORK + ["--init", "--user-id", USER2, "--journal-dir", str(folder)], secrets=INIT2)
        assert init.code == 1 and "profile 'default'" in init.err and init.asked == [], folder
    assert not profile_dir(isolated_home, "work").exists()


def test_default_cannot_join_a_journal_of_a_named_profile(fast, cli, tmp_path, isolated_home):
    shared = tmp_path / "synced"
    assert cli(WORK + ["--init", "--user-id", USER2, "--journal-dir", str(shared)], secrets=INIT2).code == 0
    join = cli(["--join", "--user-id", USER2, "--journal-dir", str(shared)], secrets=[ACCESS2], inputs=[""])
    assert join.code == 1 and "profile 'work'" in join.err
    assert not (base(isolated_home) / "config").exists()


def test_opening_a_journal_of_another_profile_is_refused(ready, work, cli, isolated_home):
    config_path = profile_dir(isolated_home, "work") / "config"
    config = config_of(isolated_home, "work")
    config["journal_dir"] = str(base(isolated_home) / "journal")       # a hand-edited config
    config_path.write_text(json.dumps(config), encoding="utf-8")
    for prefix, other in ((WORK, "default"), ([], "work")):
        result = cli(prefix + ["--list"], secrets=[ACCESS])
        assert result.code == 1 and f"profile '{other}'" in result.err and result.asked == []
        derived = cli(prefix + ["github.com"], secrets=SECRETS)
        assert derived.code == 1 and "Password:" not in derived.out


def test_an_unavailable_journal_of_another_profile_does_not_block(ready, work, cli, isolated_home):
    os.unlink(profile_dir(isolated_home, "work") / "journal" / "keys.pw3")
    assert cli(["--list"], secrets=[ACCESS]).code == 0
    (profile_dir(isolated_home, "work") / "journal" / "keys.pw3").write_bytes(b"not a keys file")
    assert cli(["--list"], secrets=[ACCESS]).code == 0


def test_init_and_join_name_the_profiles_they_could_not_compare(devices, cli, tmp_path, monkeypatch):
    on, shared = devices
    go_home(monkeypatch, tmp_path / "c")
    home_c = tmp_path / "c"
    for name, user in (("work", USER2), ("home", "outro@example.com")):
        assert cli(["--profile", name, "--init", "--user-id", user], secrets=INIT2).code == 0
    os.unlink(profile_dir(home_c, "work") / "journal" / "keys.pw3")
    join = ["--join", "--user-id", USER, "--journal-dir", str(shared)]

    # One unreadable journal: one warning naming it, at --init and at --join.
    init = cli(["--init", "--user-id", USER, "--journal-dir", str(shared)], secrets=INIT)
    assert init.code == 1 and "use --join" in init.err
    warning = "Warning: could not compare with profile 'work': its journal is not readable now."
    assert init.out.count("could not compare") == 1 and warning in init.out

    (profile_dir(home_c, "home") / "journal" / "keys.pw3").write_bytes(b"damaged")
    joined = cli(join, secrets=[ACCESS], inputs=[""])
    assert joined.code == 0, joined.err
    assert joined.out.count("could not compare") == 1
    assert ("Warning: could not compare with profiles 'home', 'work': "
            "their journals are not readable now.") in joined.out

    # Ordinary journal opens stay quiet.
    for result in (cli(["--list"], secrets=[ACCESS]), cli(["github.com"], secrets=SECRETS)):
        assert result.code == 0 and "could not compare" not in result.out + result.err


def test_nothing_to_warn_about_when_every_journal_is_readable(fast, cli, tmp_path):
    assert cli(WORK + ["--init", "--user-id", USER2], secrets=INIT2).code == 0
    result = cli(["--init", "--user-id", USER, "--journal-dir", str(tmp_path / "mine")], secrets=INIT)
    assert result.code == 0 and "could not compare" not in result.out


@pytest.mark.parametrize("where", [".", ".passweird", ".passweird/v3", ".passweird/v3/profiles",
                                   ".passweird/v3/profiles/work"])
def test_a_journal_folder_never_holds_local_state(fast, cli, isolated_home, where):
    folder = isolated_home / where
    init = cli(WORK + ["--init", "--user-id", USER2, "--journal-dir", str(folder)], secrets=INIT2)
    assert init.code == 1 and "local state" in init.err and init.asked == []
    join = cli(WORK + ["--join", "--user-id", USER2, "--journal-dir", str(folder)], secrets=[ACCESS2])
    assert join.code == 1 and "local state" in join.err and join.asked == []
    assert not profile_dir(isolated_home, "work").exists()


def test_default_journal_folder_may_not_hold_local_state_either(fast, cli, isolated_home):
    result = cli(["--init", "--user-id", USER, "--journal-dir", str(isolated_home / ".passweird")], secrets=INIT)
    assert result.code == 1 and "local state" in result.err
    assert not (base(isolated_home) / "config").exists()


# A profile directory made later must not land in a journal folder either.

@pytest.mark.parametrize("name, where", [
    ("default", ".passweird/v3/profiles"), ("default", ".passweird/v3/profiles/shared"),
    ("default", ".passweird/v3/profiles/work/journal"),
    ("work", ".passweird/v3/profiles/shared"), ("work", ".passweird/v3/profiles/home/journal"),
])
def test_no_journal_folder_inside_the_profiles_directory(fast, cli, isolated_home, name, where):
    select, folder = ["--profile", name], str(isolated_home / where)
    init = cli(select + ["--init", "--user-id", USER2, "--journal-dir", folder], secrets=INIT2)
    assert init.code == 1 and "where profile directories are created" in init.err and init.asked == []
    join = cli(select + ["--join", "--user-id", USER2, "--journal-dir", folder], secrets=[ACCESS2], inputs=[""])
    assert join.code == 1 and "where profile directories are created" in join.err and join.asked == []
    assert not (isolated_home / ".passweird").exists()


def test_a_named_profile_may_keep_its_journal_inside_its_own_directory(fast, cli, isolated_home):
    folder = profile_dir(isolated_home, "work") / "synced"
    assert cli(WORK + ["--init", "--user-id", USER2, "--journal-dir", str(folder)], secrets=INIT2).code == 0
    assert cli(WORK + ["--list"], secrets=[ACCESS2]).code == 0


@pytest.mark.parametrize("owner, folder, created", [("default", ".passweird/v3/profiles", "work"),
                                                    ("work", ".passweird/v3/profiles/shared", "shared")])
def test_init_does_not_create_a_profile_inside_a_journal_folder(fast, cli, isolated_home, owner, folder, created):
    assert cli(["--profile", owner, "--init", "--user-id", USER], secrets=INIT).code == 0
    point_journal(isolated_home, owner, isolated_home / folder)     # made before this check, or edited
    init = cli(["--profile", created, "--init", "--user-id", USER2, "--keep-recovery-file"], secrets=INIT2)
    assert init.code == 1 and f"journal folder of profile '{owner}'" in init.err and init.asked == []
    assert not profile_dir(isolated_home, created).exists()


def test_join_does_not_create_a_profile_inside_a_journal_folder(devices, cli, tmp_path, monkeypatch):
    on, shared = devices
    home = tmp_path / "c"
    go_home(monkeypatch, home)
    assert cli(["--init", "--user-id", USER2], secrets=INIT2).code == 0
    point_journal(home, "default", base(home) / "profiles")
    joined = cli(WORK + ["--join", "--user-id", USER, "--journal-dir", str(shared)], secrets=[ACCESS], inputs=[""])
    assert joined.code == 1 and "journal folder of profile 'default'" in joined.err and joined.asked == []
    assert not profile_dir(home, "work").exists()


def test_the_local_state_check_runs_at_every_journal_open(work, cli, isolated_home):
    config_path = profile_dir(isolated_home, "work") / "config"
    config = config_of(isolated_home, "work")
    config["journal_dir"] = str(isolated_home)
    config_path.write_text(json.dumps(config), encoding="utf-8")
    result = cli(WORK + ["--list"], secrets=[ACCESS2])
    assert result.code == 1 and "local state" in result.err and result.asked == []


@pytest.mark.parametrize("command", ["--change-access-password", "--recover"])
def test_access_password_commands_refuse_the_journal_of_another_profile(ready, cli, isolated_home, tmp_path,
                                                                         command):
    # "work" has the user id and every secret of default (allowed, with the
    # warning of §6.3), so only the checks of §6 keep it out of default's journal.
    assert cli(WORK + ["--init", "--user-id", USER], secrets=INIT).code == 0
    recovery = tmp_path / "recovery.txt"
    recovery.write_text(ready.recovery_text, encoding="utf-8")
    argv, secrets = {
        "--change-access-password": ([command], [ACCESS, NEW_ACCESS, NEW_ACCESS]),
        "--recover": ([command, "--recovery-file", str(recovery)], [MASTER, BOOST, NEW_ACCESS, NEW_ACCESS]),
    }[command]
    point_journal(isolated_home, "work", base(isolated_home) / "journal")
    before = snapshot(base(isolated_home), skip=base(isolated_home) / "profiles")
    result = cli(WORK + argv, secrets=secrets)
    assert result.code == 1 and "profile 'default'" in result.err and result.asked == []
    assert snapshot(base(isolated_home), skip=base(isolated_home) / "profiles") == before


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links")
def test_changing_the_access_password_through_a_repointed_link_is_refused(ready, cli, isolated_home, tmp_path):
    link, real = tmp_path / "work-journal", tmp_path / "work-real"
    real.mkdir()
    link.symlink_to(real, target_is_directory=True)
    assert cli(WORK + ["--init", "--user-id", USER2, "--journal-dir", str(link)], secrets=INIT2).code == 0
    link.unlink()
    link.symlink_to(base(isolated_home) / "journal", target_is_directory=True)     # re-pointed later
    before = snapshot(base(isolated_home), skip=base(isolated_home) / "profiles")
    result = cli(WORK + ["--change-access-password"], secrets=[ACCESS, NEW_ACCESS, NEW_ACCESS])
    assert result.code == 1 and "profile 'default'" in result.err and result.asked == []
    assert snapshot(base(isolated_home), skip=base(isolated_home) / "profiles") == before
    assert cli(["--list"], secrets=[ACCESS]).code == 1          # default sees work on its journal too


@pytest.mark.parametrize("where, message", [("default's journal", "profile 'default'"),
                                            ("the home directory", "local state")])
def test_every_command_that_opens_keys_pw3_runs_the_checks(ready, work, cli, isolated_home, tmp_path,
                                                           where, message):
    recovery = tmp_path / "recovery.txt"
    recovery.write_text(work.recovery_text, encoding="utf-8")
    sites = tmp_path / "sites.txt"
    sites.write_text("example.org\n", encoding="utf-8")
    keyfile = tmp_path / "k.pw3f"
    assert cli(WORK + ["--gen-keyfile", str(keyfile)], secrets=[MASTER2, BOOST2]).code == 0
    point_journal(isolated_home, "work",
                  base(isolated_home) / "journal" if where == "default's journal" else isolated_home)
    before = snapshot(base(isolated_home), skip=base(isolated_home) / "profiles")
    commands = [
        (["github.com"], SECRETS2), (["github.com", "--totp"], SECRETS2),
        (["--list"], [ACCESS2]), (["--show", "github.com"], [ACCESS2]), (["--history"], [ACCESS2]),
        (["--edit", "github.com", "--notes", "x"], [ACCESS2]), (["--resolve", "github.com"], [ACCESS2]),
        (["--delete", "github.com"], [ACCESS2]), (["--import-list", str(sites)], [ACCESS2]),
        (["--change-access-password"], [ACCESS2, NEW_ACCESS, NEW_ACCESS]),
        (["--recover", "--recovery-file", str(recovery)], [MASTER2, BOOST2, NEW_ACCESS, NEW_ACCESS]),
        (["--print-recovery"], SECRETS2), (["--pin-key-file", str(keyfile)], SECRETS2),
        (["--export-kdbx", str(tmp_path / "x.kdbx")], SECRETS2),
        (["--mass-rekey", "--export-kdbx", str(tmp_path / "y.kdbx")], SECRETS2),
        (["--migrate-v2", "--keep-v2-files"], ["senha mestra antiga", ACCESS2]),
    ]
    for argv, secrets in commands:
        result = cli(WORK + argv, secrets=secrets)
        assert result.code == 1 and message in result.err, (argv, result.err)
        assert "Password:" not in result.out and "Access password changed" not in result.out, argv
    assert snapshot(base(isolated_home), skip=base(isolated_home) / "profiles") == before


def test_init_warns_when_another_profile_has_the_same_user_id(ready, cli):
    same = cli(WORK + ["--init", "--user-id", " " + USER.upper()], secrets=INIT2)
    assert same.code == 0 and "same user id" in same.out and "'default'" in same.out
    assert same.out.index("same user id") < same.out.index("Fingerprint:")
    other = cli(["--profile", "home", "--init", "--user-id", "outro@example.com"], secrets=INIT2)
    assert other.code == 0 and "same user id" not in other.out


# --- keyfile pin (§9) --------------------------------------------------------

@pytest.fixture
def keyfile(ready, cli, tmp_path):
    path = tmp_path / "factor.pw3f"
    assert cli(["--gen-keyfile", str(path)], secrets=[MASTER, BOOST]).code == 0
    return path


@pytest.fixture
def pinned(keyfile, cli):
    result = cli(["--pin-key-file", str(keyfile)], secrets=SECRETS)
    assert result.code == 0, result.err
    return keyfile


def expected(path=None, site="github.com", master=MASTER, boost=BOOST, user=USER):
    with derive.Session.open(master, boost, user) as session:
        if path is not None:
            session.use_keyfile(keys.open_keyfile(path.read_bytes(), session.prk_none))
        return session.password(site), session.totp_secret(site)


def test_pin_records_path_and_hash(pinned, isolated_home):
    config = config_of(isolated_home)
    assert config["key_file"] == str(pinned) and os.path.isabs(config["key_file"])
    assert config["key_file_sha256"] == hashlib.sha256(pinned.read_bytes()).hexdigest()


def test_pin_asks_master_boost_and_opens_the_registry(keyfile, cli):
    result = cli(["--pin-key-file", str(keyfile)], secrets=SECRETS)
    assert result.code == 0 and result.asked == ["Master password: ", "Boost: ", "Access password: "]
    assert "Fingerprint:" in result.out


def test_a_pinned_profile_derives_with_its_keyfile(pinned, cli):
    password, totp = expected(pinned)
    assert password != expected()[0]
    assert cli(["github.com"], secrets=SECRETS).password == password
    assert cli(["github.com", "--no-journal"], secrets=[MASTER, BOOST]).password == password
    assert cli(["github.com", "--totp"], secrets=SECRETS).value("TOTP secret (Base32):") == totp


def test_a_missing_or_different_keyfile_stops_before_argon2(pinned, cli, tmp_path, stretches):
    other = tmp_path / "other.pw3f"
    assert cli(["--gen-keyfile", str(other)], secrets=[MASTER, BOOST]).code == 0
    stashed = tmp_path / "stashed.pw3f"
    shutil.move(pinned, stashed)
    del stretches[:]
    attempts = [(["github.com"], SECRETS), (["github.com", "--no-journal"], [MASTER, BOOST]),
                (["github.com", "--ssh"], SECRETS),
                (["--export-kdbx", str(tmp_path / "x.kdbx")], SECRETS + ["k", "k"]),
                (["--mass-rekey", "--export-kdbx", str(tmp_path / "y.kdbx"), "--drop-key-file"], SECRETS)]
    for argv, secrets in attempts:
        result = cli(argv, secrets=secrets)
        assert result.code == 1 and str(pinned) in result.err and result.asked == [], argv
    shutil.copy(other, pinned)                          # same path, another keyfile
    for argv, secrets in attempts:
        result = cli(argv, secrets=secrets)
        assert result.code == 1 and str(pinned) in result.err and result.asked == [], argv
    assert stretches == []
    shutil.copy(stashed, pinned)
    assert cli(["github.com"], secrets=SECRETS).password == expected(stashed)[0]


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="POSIX permissions, not root")
def test_an_unreadable_keyfile_stops_before_argon2(pinned, cli, stretches):
    os.chmod(pinned, 0)
    try:
        result = cli(["github.com"], secrets=SECRETS)
    finally:
        os.chmod(pinned, 0o600)
    assert result.code == 1 and str(pinned) in result.err and result.asked == [] and stretches == []


def test_key_file_flag_on_a_pinned_profile(pinned, cli, tmp_path, stretches):
    other = tmp_path / "other.pw3f"
    assert cli(["--gen-keyfile", str(other)], secrets=[MASTER, BOOST]).code == 0
    del stretches[:]
    refused = cli(["github.com", "--key-file", str(other)], secrets=SECRETS)
    assert refused.code == 1 and str(other) in refused.err and refused.asked == [] and stretches == []
    copy = tmp_path / "copy.pw3f"
    shutil.copy(pinned, copy)
    pinned.unlink()                                     # the copy stands in for a lost original
    assert cli(["github.com", "--key-file", str(copy)], secrets=SECRETS).password == expected(copy)[0]


def test_pinning_a_registry_with_entries_needs_force(keyfile, cli, isolated_home):
    cli(["github.com"], secrets=SECRETS)
    refused = cli(["--pin-key-file", str(keyfile)], secrets=SECRETS)
    assert refused.code == 1 and "--force" in refused.err and "--mass-rekey" in refused.err
    assert "key_file" not in config_of(isolated_home)
    assert cli(["--pin-key-file", str(keyfile), "--force"], secrets=SECRETS).code == 0
    assert config_of(isolated_home)["key_file"] == str(keyfile)


def test_deleted_entries_count_for_force_too(keyfile, cli, isolated_home):
    # A deleted site created again resumes its counter and gives back its old
    # password; once pinned, it would silently give another one.
    before = cli(["github.com"], secrets=SECRETS).password
    assert cli(["--delete", "github.com"], secrets=[ACCESS]).code == 0
    assert "empty" in cli(["--list"], secrets=[ACCESS]).out
    refused = cli(["--pin-key-file", str(keyfile)], secrets=SECRETS)
    assert refused.code == 1 and "--force" in refused.err and "1 entry (deleted" in refused.err
    assert "key_file" not in config_of(isolated_home)
    assert cli(["github.com"], secrets=SECRETS).password == before


def test_pinning_right_after_init_needs_no_force(fast, cli, tmp_path, isolated_home):
    assert cli(WORK + ["--init", "--user-id", USER2], secrets=INIT2).code == 0
    keyfile = tmp_path / "k.pw3f"
    assert cli(WORK + ["--gen-keyfile", str(keyfile)], secrets=[MASTER2, BOOST2]).code == 0
    assert cli(WORK + ["--pin-key-file", str(keyfile)], secrets=SECRETS2).code == 0
    assert config_of(isolated_home, "work")["key_file"] == str(keyfile)


def test_pin_refuses_a_keyfile_of_other_secrets_or_a_non_keyfile(ready, cli, tmp_path, isolated_home):
    foreign = tmp_path / "foreign.pw3f"
    assert cli(["--gen-keyfile", str(foreign), "--user-id", "outro@example.com"], secrets=[MASTER, BOOST]).code == 0
    refused = cli(["--pin-key-file", str(foreign)], secrets=SECRETS)
    assert refused.code == 1 and str(foreign) in refused.err
    junk = tmp_path / "junk"
    junk.write_bytes(b"x" * 65)
    refused = cli(["--pin-key-file", str(junk)], secrets=SECRETS)
    assert refused.code == 1 and str(junk) in refused.err and refused.asked == []
    missing = cli(["--pin-key-file", str(tmp_path / "missing")], secrets=SECRETS)
    assert missing.code == 1 and missing.asked == []
    assert "key_file" not in config_of(isolated_home)


def test_a_copy_with_the_pinned_hash_moves_the_pin_without_secrets(pinned, cli, tmp_path, isolated_home):
    cli(["github.com"], secrets=SECRETS)                # entries do not matter for a move
    moved = tmp_path / "moved" / "factor.pw3f"
    moved.parent.mkdir()
    shutil.copy(pinned, moved)
    pinned.unlink()
    result = cli(["--pin-key-file", str(moved)])
    assert result.code == 0 and result.asked == [] and str(moved) in result.out
    assert config_of(isolated_home)["key_file"] == str(moved)
    assert cli(["github.com"], secrets=SECRETS).password == expected(moved)[0]


def test_unpin(pinned, cli, isolated_home):
    result = cli(["--unpin-key-file"])
    assert result.code == 0 and result.asked == [] and "WARNING" in result.out
    config = config_of(isolated_home)
    assert "key_file" not in config and "key_file_sha256" not in config
    assert cli(["github.com"], secrets=SECRETS).password == expected()[0]
    again = cli(["--unpin-key-file"])
    assert again.code == 0 and "no keyfile" in again.out.lower()


def test_mass_rekey_on_a_pinned_profile_must_be_told_about_the_keyfile(pinned, cli, tmp_path, stretches):
    cli(["github.com"], secrets=SECRETS)
    del stretches[:]
    out = str(tmp_path / "rekey.kdbx")
    neither = cli(["--mass-rekey", "--export-kdbx", out], secrets=SECRETS)
    assert neither.code == 1 and "--new-key-file" in neither.err and "--drop-key-file" in neither.err
    assert neither.asked == [] and stretches == []
    both = cli(["--mass-rekey", "--export-kdbx", out, "--drop-key-file", "--new-key-file", str(pinned)],
               secrets=SECRETS)
    assert both.code == 1 and both.asked == []


NEW_MASTER, NEW_BOOST = "outra mestra", "novo reforco de cinco palavras aqui"
REKEY = SECRETS + [NEW_MASTER, NEW_MASTER, NEW_BOOST, NEW_BOOST, "k", "k"]


def test_mass_rekey_drop_key_file(pinned, cli, tmp_path, isolated_home):
    pykeepass = pytest.importorskip("pykeepass")
    cli(["github.com"], secrets=SECRETS)
    out = tmp_path / "rekey.kdbx"
    result = cli(["--mass-rekey", "--export-kdbx", str(out), "--drop-key-file"], secrets=REKEY)
    assert result.code == 0, result.err
    database = pykeepass.PyKeePass(str(out), password="k")
    assert database.find_entries(title="github.com (old)", first=True).password == expected(pinned)[0]
    new = expected(master=NEW_MASTER, boost=NEW_BOOST)[0]
    assert database.find_entries(title="github.com (new)", first=True).password == new
    assert "key_file" not in config_of(isolated_home)
    assert cli(["github.com"], secrets=[NEW_MASTER, NEW_BOOST, ACCESS]).password == new


def test_mass_rekey_new_key_file_becomes_the_pin(pinned, cli, tmp_path, isolated_home):
    pykeepass = pytest.importorskip("pykeepass")
    cli(["github.com"], secrets=SECRETS)
    new_keyfile = tmp_path / "new.pw3f"
    assert cli(["--gen-keyfile", str(new_keyfile)], secrets=[NEW_MASTER, NEW_BOOST]).code == 0
    out = tmp_path / "rekey.kdbx"
    result = cli(["--mass-rekey", "--export-kdbx", str(out), "--new-key-file", str(new_keyfile)], secrets=REKEY)
    assert result.code == 0, result.err
    config = config_of(isolated_home)
    assert config["key_file"] == str(new_keyfile)
    assert config["key_file_sha256"] == hashlib.sha256(new_keyfile.read_bytes()).hexdigest()
    new = expected(new_keyfile, master=NEW_MASTER, boost=NEW_BOOST)[0]
    assert pykeepass.PyKeePass(str(out), password="k").find_entries(
        title="github.com (new)", first=True).password == new
    assert cli(["github.com"], secrets=[NEW_MASTER, NEW_BOOST, ACCESS]).password == new


def test_without_a_pin_mass_rekey_keeps_todays_meaning(ready, cli, tmp_path, isolated_home):
    pytest.importorskip("pykeepass")
    cli(["github.com"], secrets=SECRETS)
    new_keyfile = tmp_path / "new.pw3f"
    assert cli(["--gen-keyfile", str(new_keyfile)], secrets=[NEW_MASTER, NEW_BOOST]).code == 0
    result = cli(["--mass-rekey", "--export-kdbx", str(tmp_path / "r.kdbx"), "--new-key-file", str(new_keyfile)],
                 secrets=REKEY)
    assert result.code == 0, result.err
    assert "key_file" not in config_of(isolated_home)
    dropped = cli(["--mass-rekey", "--export-kdbx", str(tmp_path / "s.kdbx"), "--drop-key-file"], secrets=REKEY)
    assert dropped.code == 1 and "no keyfile" in dropped.err.lower() and dropped.asked == []


def test_drop_key_file_belongs_to_mass_rekey(pinned, cli):
    assert cli(["github.com", "--drop-key-file"], secrets=SECRETS).code == 2


def test_init_with_key_file_pins_at_creation(fast, cli, tmp_path, isolated_home):
    keyfile = tmp_path / "k.pw3f"
    assert cli(["--gen-keyfile", str(keyfile), "--user-id", USER], secrets=[MASTER, BOOST]).code == 0
    assert not (isolated_home / ".passweird").exists()
    result = cli(["--init", "--user-id", USER, "--key-file", str(keyfile)], secrets=INIT)
    assert result.code == 0, result.err
    config = config_of(isolated_home)
    assert config["key_file"] == str(keyfile)
    assert config["key_file_sha256"] == hashlib.sha256(keyfile.read_bytes()).hexdigest()
    assert cli(["github.com"], secrets=SECRETS).password == expected(keyfile)[0]


def test_init_refuses_a_bad_key_file_and_writes_nothing(fast, cli, tmp_path, isolated_home, stretches):
    foreign = tmp_path / "foreign.pw3f"
    assert cli(["--gen-keyfile", str(foreign), "--user-id", "outro@example.com"], secrets=[MASTER, BOOST]).code == 0
    refused = cli(["--init", "--user-id", USER, "--key-file", str(foreign)], secrets=INIT)
    assert refused.code == 1 and str(foreign) in refused.err
    assert not (isolated_home / ".passweird").exists()
    del stretches[:]
    missing = cli(["--init", "--user-id", USER, "--key-file", str(tmp_path / "missing")], secrets=INIT)
    assert missing.code == 1 and missing.asked == [] and stretches == []
    assert not (isolated_home / ".passweird").exists()


def test_join_asks_whether_a_keyfile_is_used(devices, cli, tmp_path, monkeypatch):
    on, shared = devices
    assert "key_file" not in config_of(tmp_path / "b")             # answered with an empty line
    on("a")
    keyfile = tmp_path / "factor.pw3f"
    assert cli(["--gen-keyfile", str(keyfile)], secrets=[MASTER, BOOST]).code == 0
    assert cli(["--pin-key-file", str(keyfile)], secrets=SECRETS).code == 0
    password = cli(["github.com"], secrets=SECRETS).password
    join = ["--join", "--user-id", USER, "--journal-dir", str(shared), "--secrets-stdin"]

    go_home(monkeypatch, tmp_path / "c")                            # answers with the path
    assert cli(join, stdin=f"{ACCESS}\n{keyfile}\n").code == 0
    assert config_of(tmp_path / "c")["key_file"] == str(keyfile)
    assert cli(["github.com"], secrets=SECRETS).password == password

    go_home(monkeypatch, tmp_path / "d")                            # answers with nothing
    assert cli(join, stdin=f"{ACCESS}\n\n").code == 0
    assert "key_file" not in config_of(tmp_path / "d")
    assert cli(["github.com"], secrets=SECRETS).password != password

    go_home(monkeypatch, tmp_path / "e")                            # --key-file answers it
    assert cli(join + ["--key-file", str(keyfile)], stdin=f"{ACCESS}\n").code == 0
    assert config_of(tmp_path / "e")["key_file"] == str(keyfile)

    go_home(monkeypatch, tmp_path / "f")                            # wrong password: no question
    wrong = cli(join, stdin="errada\n")
    assert wrong.code == 1 and "wrong access password" in wrong.err

    junk = tmp_path / "junk"
    junk.write_bytes(b"PW3G" + b"\x00" * 61)
    refused = cli(join, stdin=f"{ACCESS}\n{junk}\n")
    assert refused.code == 1 and str(junk) in refused.err
    assert not (tmp_path / "f" / ".passweird" / "v3" / "config").exists()


def test_join_only_checks_the_header_then_the_first_derivation_fails(devices, cli, tmp_path, monkeypatch):
    on, shared = devices
    foreign = tmp_path / "foreign.pw3f"
    assert cli(["--gen-keyfile", str(foreign), "--user-id", "outro@example.com"], secrets=[MASTER, BOOST]).code == 0
    go_home(monkeypatch, tmp_path / "c")
    join = cli(["--join", "--user-id", USER, "--journal-dir", str(shared), "--secrets-stdin"],
               stdin=f"{ACCESS}\n{foreign}\n")
    assert join.code == 0 and join.asked == []
    derived = cli(["github.com"], secrets=SECRETS)
    assert derived.code == 1 and str(foreign) in derived.err and "Password:" not in derived.out


# --- vectors under any profile -----------------------------------------------

def test_stretch_vector_under_a_named_profile(cli, monkeypatch):
    monkeypatch.setattr(keys, "DEFAULT_ACCESS_PARAMS", (1024, 1, 1))
    vector = load("derivation.json")["stretch"][0]
    master, boost = vector["master"], vector["boost"]
    assert cli(WORK + ["--init", "--user-id", vector["user_id"]],
               secrets=[master, master, boost, boost, ACCESS, ACCESS]).code == 0
    result = cli(WORK + ["github.com"], secrets=[master, boost, ACCESS])
    assert result.password == vector["password_github"]
    assert result.value("Fingerprint:") == vector["fingerprint"]


def test_password_vectors_under_a_named_profile(fast, cli, tmp_path, monkeypatch):
    vectors = load("derivation.json")
    k0 = bytes.fromhex(vectors["fixed_k0_hex"])
    monkeypatch.setattr(derive, "stretch", lambda *args: bytearray(k0))
    assert cli(WORK + ["--init", "--user-id", USER], secrets=INIT).code == 0
    with derive.Session(bytearray(k0), USER) as session:
        keyfile = tmp_path / "fixed.pw3f"
        keyfile.write_bytes(keys.build_keyfile(session.prk_none, bytes.fromhex(vectors["fixed_keyfile_hex"])))
    flags = {1: "-l", 2: "-U", 4: "-n", 8: "-s"}
    for v in vectors["passwords"]:
        argv = WORK + [v["site"], "--no-journal", "-u", v["login"], "-C", str(v["counter"]), "-L", str(v["length"])]
        argv += [flag for bit, flag in flags.items() if not v["classes"] & bit]
        if v["label"] == "keyfile-factor":
            argv += ["--key-file", str(keyfile)]
        result = cli(argv, secrets=[MASTER, BOOST])
        assert result.password == v["expected_password"], v["label"]
        assert result.value("Fingerprint:") == vectors["fingerprint"]["expected"]
