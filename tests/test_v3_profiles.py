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


@pytest.fixture
def work(fast, cli):
    """A named profile with its own secrets, user id and journal."""
    result = cli(WORK + ["--init", "--user-id", USER2], secrets=INIT2)
    assert result.code == 0, result.err
    return result


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
    ["--new-device-id"], ["--gen-keyfile", "k.pw3f", "--user-id", USER],
    ["--print-recovery"], ["--recover"], ["--change-access-password"],
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
        assert "Recovery file: not kept" in block


def test_list_profiles_shows_a_kept_recovery_file(fast, cli):
    assert cli(WORK + ["--init", "--user-id", USER2, "--keep-recovery-file"], secrets=INIT2).code == 0
    out = cli(["--list-profiles"]).out
    assert out.startswith("work\n") and "Recovery file: kept" in out


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


def test_the_local_state_check_runs_at_every_journal_open(work, cli, isolated_home):
    config_path = profile_dir(isolated_home, "work") / "config"
    config = config_of(isolated_home, "work")
    config["journal_dir"] = str(isolated_home)
    config_path.write_text(json.dumps(config), encoding="utf-8")
    result = cli(WORK + ["--list"], secrets=[ACCESS2])
    assert result.code == 1 and "local state" in result.err and result.asked == []


def test_init_warns_when_another_profile_has_the_same_user_id(ready, cli):
    same = cli(WORK + ["--init", "--user-id", " " + USER.upper()], secrets=INIT2)
    assert same.code == 0 and "same user id" in same.out and "'default'" in same.out
    assert same.out.index("same user id") < same.out.index("Fingerprint:")
    other = cli(["--profile", "home", "--init", "--user-id", "outro@example.com"], secrets=INIT2)
    assert other.code == 0 and "same user id" not in other.out


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
