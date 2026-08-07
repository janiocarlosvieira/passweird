import csv
import os
import re
import sys
from passweird import crypto, main, storage


import pytest


_LOG_TIMESTAMP = re.compile(r"^\d{14} ", re.MULTILINE)


def _without_timestamp(output):
    """
    Strips the log line's wall-clock stamp before comparing two runs.

    build_and_log_line prefixes every summary line with a YYYYMMDDHHMMSS date_str,
    so comparing raw stdout across two runs is a race: it fails whenever they
    straddle a second boundary, which is what happened on the slower Windows
    runner. The stamp is a property of the clock, not of the derivation - and the
    derivation is what these tests actually assert. Everything else in the line,
    including the pwd: and key: fingerprints, is still compared.
    """
    return _LOG_TIMESTAMP.sub("<timestamp> ", output)



def _run(monkeypatch, argv, getpass_inputs=None, input_inputs=None):
    monkeypatch.setattr(sys, "argv", ["main.py"] + argv)
    if getpass_inputs is not None:
        it = iter(getpass_inputs)
        monkeypatch.setattr("getpass.getpass", lambda prompt="": next(it))
    if input_inputs is not None:
        it2 = iter(input_inputs)
        monkeypatch.setattr("builtins.input", lambda prompt="": next(it2))
    with pytest.raises(SystemExit) as exc:
        main.main()
    return exc.value.code


def _run_no_exit(monkeypatch, argv, getpass_inputs=None, input_inputs=None):
    monkeypatch.setattr(sys, "argv", ["main.py"] + argv)
    if getpass_inputs is not None:
        it = iter(getpass_inputs)
        monkeypatch.setattr("getpass.getpass", lambda prompt="": next(it))
    if input_inputs is not None:
        it2 = iter(input_inputs)
        monkeypatch.setattr("builtins.input", lambda prompt="": next(it2))
    main.main()


def test_generate_config_flag(capsys):
    code = None
    try:
        sys.argv = ["main.py", "-g"]
        main.main()
    except SystemExit as e:
        code = e.code
    assert code == 0
    config_path = os.path.expanduser("~/.passweird/passweird.cfg")
    assert os.path.exists(config_path)


def test_save_settings_flag(monkeypatch):
    code = _run(monkeypatch, ["--save-settings", "-L", "24", "-p"])
    assert code == 0
    cfg = storage.load_settings()
    assert cfg["length"] == 24
    assert cfg["paranoid"] is True


def test_standard_password_generation(monkeypatch, capsys):
    _run_no_exit(monkeypatch, ["testapp", "-T", ""], getpass_inputs=["mymaster"])
    out = capsys.readouterr().out
    assert "Generated Password" in out or "Senha Gerada" in out


def test_no_print_hash_suppresses_summary_line(monkeypatch, capsys):
    _run_no_exit(monkeypatch, ["testapp", "-T", "", "--no-print-hash"], getpass_inputs=["mymaster"])
    out = capsys.readouterr().out
    assert "ver:v2" not in out


def test_write_flag_disables_logging(monkeypatch):
    _run_no_exit(monkeypatch, ["testapp", "-T", "", "-w"], getpass_inputs=["mymaster"])
    mh = crypto.modified_hash("mymaster")
    assert storage.read_logs_from_file(mh) == []


def test_master_pass_flag(monkeypatch, capsys):
    _run_no_exit(monkeypatch, ["testapp", "-T", "", "--master-pass", "mymaster"])
    out = capsys.readouterr().out
    assert "SECURITY WARNING" in out or "AVISO" in out or "SEGURANÇA" in out


def test_master_file_flag(monkeypatch, tmp_path):
    master_file = tmp_path / "master.txt"
    master_file.write_text("mymaster\n")
    _run_no_exit(monkeypatch, ["testapp", "-T", "", "--master-file", str(master_file)])
    mh = crypto.modified_hash("mymaster")
    records = storage.read_logs_from_file(mh)
    assert len(records) == 1


def test_temporal_secret_file_flag(monkeypatch, tmp_path):
    temporal_file = tmp_path / "temporal.txt"
    temporal_file.write_text("2026Q1\n")
    # blank input -> Enter to repeat the file-provided default
    _run_no_exit(monkeypatch, ["testapp", "--temporal-secret-file", str(temporal_file)],
                 getpass_inputs=["mymaster"], input_inputs=[""])
    mh = crypto.modified_hash("mymaster")
    ah = crypto.modified_hash("testapp")
    app_sum = crypto.summarize_hash(ah)
    matches = storage.find_in_log(app_sum, "2026Q1", mh)
    assert len(matches) == 1


def test_register_and_check_master(monkeypatch, capsys):
    code = _run(monkeypatch, ["--register-master"], getpass_inputs=["mymaster", "mymaster"])
    assert code == 0

    # correct password passes the check
    _run_no_exit(monkeypatch, ["testapp", "-T", ""], getpass_inputs=["mymaster"])

    # wrong password is rejected
    code2 = _run(monkeypatch, ["testapp", "-T", ""], getpass_inputs=["WRONG"])
    assert code2 == 1
    err = capsys.readouterr().out
    assert "CRITICAL" in err or "CRÍTICO" in err


def test_change_mode(monkeypatch, capsys):
    _run_no_exit(
        monkeypatch, ["-c", "-T", ""],
        getpass_inputs=["oldmaster", "newmaster", "oldapp", "newapp"],
        input_inputs=[""],
    )
    out = capsys.readouterr().out
    assert "Old password" in out or "Senha antiga" in out
    assert "New password" in out or "Nova senha" in out

    old_mh = crypto.modified_hash("oldmaster")
    new_mh = crypto.modified_hash("newmaster")
    assert len(storage.read_logs_from_file(old_mh)) == 1
    assert len(storage.read_logs_from_file(new_mh)) == 1


def test_batch_mode_plaintext(monkeypatch, tmp_path):
    batch_file = tmp_path / "batch.txt"
    batch_file.write_text("switch-core-01 core switch\nservidor-zabbix monitoring\n")
    _run_no_exit(monkeypatch, ["-f", str(batch_file), "-T", ""], getpass_inputs=["mymaster"])

    mh = crypto.modified_hash("mymaster")
    records = storage.read_logs_from_file(mh)
    assert len(records) == 2


def test_batch_mode_csv(monkeypatch, tmp_path):
    csv_file = tmp_path / "batch.csv"
    with open(csv_file, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["app", "identifiers"])
        w.writerow(["switch-core-01", "core switch"])
        w.writerow(["servidor-zabbix", "monitoring"])
    _run_no_exit(monkeypatch, ["-f", str(csv_file), "-T", ""], getpass_inputs=["mymaster"])

    mh = crypto.modified_hash("mymaster")
    records = storage.read_logs_from_file(mh)
    assert len(records) == 2


def test_gen_keyfile_random_then_key_file_roundtrip(monkeypatch, tmp_path, capsys):
    keyfile_path = str(tmp_path / "pendrive.key")
    code = _run(monkeypatch, ["--gen-keyfile", keyfile_path], getpass_inputs=["mymaster"])
    assert code == 0
    assert os.path.exists(keyfile_path)
    capsys.readouterr()  # discard --gen-keyfile's own output before comparing the two runs below

    _run_no_exit(monkeypatch, ["testapp", "--key-file", keyfile_path, "-T", ""], getpass_inputs=["mymaster"])
    out1 = capsys.readouterr().out

    _run_no_exit(monkeypatch, ["testapp", "--key-file", keyfile_path, "-T", ""], getpass_inputs=["mymaster"])
    out2 = capsys.readouterr().out
    assert _without_timestamp(out1) == _without_timestamp(out2)

    code_wrong = _run(monkeypatch, ["testapp", "--key-file", keyfile_path, "-T", ""], getpass_inputs=["WRONGMASTER"])
    assert code_wrong == 1


def test_gen_keyfile_recoverable(monkeypatch, tmp_path):
    keyfile_a = str(tmp_path / "recoverable_a.key")
    keyfile_b = str(tmp_path / "recoverable_b.key")

    code = _run(monkeypatch, ["--gen-keyfile", keyfile_a, "--recoverable"],
                getpass_inputs=["mymaster", "recovery phrase", "recovery phrase"])
    assert code == 0

    code2 = _run(monkeypatch, ["--gen-keyfile", keyfile_b, "--recoverable"],
                 getpass_inputs=["mymaster", "recovery phrase", "recovery phrase"])
    assert code2 == 0

    h_a = crypto.modified_hash("mymaster", keyfile_path=keyfile_a)
    h_b = crypto.modified_hash("mymaster", keyfile_path=keyfile_b)
    assert h_a == h_b


def test_totp_flag(monkeypatch, capsys):
    code = _run(monkeypatch, ["testapp", "--totp", "-T", ""], getpass_inputs=["mymaster"])
    assert code == 0
    out = capsys.readouterr().out
    assert "BASE32 SECRET" in out
    assert "otpauth://totp" in out


def test_pgp_flag(monkeypatch, capsys):
    if not any(os.access(os.path.join(p, "gpg"), os.X_OK) for p in os.environ.get("PATH", "").split(os.pathsep)):
        pytest.skip("gpg binary not available")
    code = _run(monkeypatch, ["testapp", "--pgp", "-T", ""], getpass_inputs=["mymaster"])
    assert code == 0
    out = capsys.readouterr().out
    assert "BEGIN PGP PUBLIC KEY BLOCK" in out
    assert "BEGIN PGP PRIVATE KEY BLOCK" in out


def test_cross_check_mismatch_warning_and_abort(monkeypatch, capsys):
    _run_no_exit(monkeypatch, ["testapp", "-T", "", "-L", "18"], getpass_inputs=["mymaster"])

    code = _run(monkeypatch, ["testapp", "-T", "", "-L", "24"],
                getpass_inputs=["mymaster"], input_inputs=["n"])
    assert code == 0
    out = capsys.readouterr().out
    assert "WARNING" in out


def test_cross_check_force_skips_warning(monkeypatch, capsys):
    _run_no_exit(monkeypatch, ["testapp", "-T", "", "-L", "18"], getpass_inputs=["mymaster"])
    _run_no_exit(monkeypatch, ["testapp", "-T", "", "-L", "24", "--force"], getpass_inputs=["mymaster"])
    out = capsys.readouterr().out
    assert "WARNING" not in out


def test_mass_rekey_end_to_end(monkeypatch, tmp_path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("switch-core-01\nservidor-zabbix\n")

    _run(monkeypatch, ["--encrypt-list", str(hosts_file), "-T", ""], getpass_inputs=["oldmaster"])

    _run_no_exit(monkeypatch, ["--mass-rekey", "-L", "18"],
                 getpass_inputs=["oldmaster", "newmaster", "newmaster"])

    new_mh = crypto.modified_hash("newmaster")
    content = storage.read_encrypted_hosts(new_mh)
    assert "switch-core-01" in content
    assert "servidor-zabbix" in content

    old_mh = crypto.modified_hash("oldmaster")
    with pytest.raises(ValueError):
        storage.read_encrypted_hosts(old_mh)


def test_rsa_flag_is_reproducible_across_runs(monkeypatch, capsys):
    code = _run(monkeypatch, ["testapp", "--rsa", "2048", "-T", ""], getpass_inputs=["mymaster"])
    assert code == 0
    first = capsys.readouterr().out
    assert "BEGIN PRIVATE KEY" in first
    assert "BEGIN CERTIFICATE" in first
    # The old --rsa path emitted this because it could not seed OpenSSL's keygen.
    assert "NOT reproducible" not in first

    code = _run(monkeypatch, ["testapp", "--rsa", "2048", "-T", ""], getpass_inputs=["mymaster"])
    assert code == 0
    assert capsys.readouterr().out == first


def test_rsa_flag_rejects_invalid_bit_sizes(monkeypatch, capsys):
    for bad in ["1024", "2049"]:
        with pytest.raises(SystemExit) as exc:
            _run_no_exit(monkeypatch, ["testapp", "--rsa", bad, "-T", ""], getpass_inputs=["mymaster"])
        assert exc.value.code != 0
        assert "--rsa" in capsys.readouterr().err


def test_rsa_temporal_secret_changes_output_and_warns(monkeypatch, capsys):
    code = _run(monkeypatch, ["testapp", "--rsa", "2048", "-T", ""], getpass_inputs=["mymaster"])
    assert code == 0
    without = capsys.readouterr().out
    # No temporal secret: the CN publishes the context, so the user must be told.
    # Asserted via the "147" figure in the hint rather than any English wording,
    # since the warning is translated and the suite runs under the system locale.
    assert "147" in without

    code = _run(monkeypatch, ["testapp", "--rsa", "2048", "-T", "frase forte 2026"],
                getpass_inputs=["mymaster"])
    assert code == 0
    with_salt = capsys.readouterr().out
    assert "147" not in with_salt
    assert with_salt != without

    code = _run(monkeypatch, ["testapp", "--rsa", "2048", "-T", "frase forte 2026"],
                getpass_inputs=["mymaster"])
    assert code == 0
    assert capsys.readouterr().out == with_salt


def test_weak_temporal_secret_warns_on_published_key_paths(monkeypatch, capsys):
    for argv, label in (
        (["testapp", "--rsa", "2048"], "rsa"),
        (["testapp", "--ssl"], "ssl"),
        (["testapp", "--ssh"], "ssh"),
    ):
        code = _run(monkeypatch, argv + ["-T", "2026/01"], getpass_inputs=["mymaster"])
        assert code == 0, label
        out = capsys.readouterr().out
        # "147" comes from the hint about deceptive strength meters and is the only
        # part of the message that survives translation unchanged.
        assert "147" in out, label


def test_strong_temporal_secret_produces_no_warning(monkeypatch, capsys):
    code = _run(monkeypatch,
                ["testapp", "--ssl", "-T", "cavalo bateria grampo correto girassol trombone"],
                getpass_inputs=["mymaster"])
    assert code == 0
    assert "147" not in capsys.readouterr().out


def test_context_leak_note_only_where_the_context_is_published(monkeypatch, capsys):
    """SSL publishes the context in the CN; the SSH public key does not."""
    _run(monkeypatch, ["testapp", "--ssl", "-T", ""], getpass_inputs=["mymaster"])
    assert "CN" in capsys.readouterr().out

    _run(monkeypatch, ["testapp", "--ssh", "-T", ""], getpass_inputs=["mymaster"])
    assert "CN" not in capsys.readouterr().out


def test_gen_temporal_flag(monkeypatch, capsys):
    code = _run(monkeypatch, ["--gen-temporal"])
    assert code == 0
    out = capsys.readouterr().out
    assert "bits" in out.lower()

    code = _run(monkeypatch, ["--gen-temporal", "4"])
    assert code == 0
    assert "bits" in capsys.readouterr().out.lower()


def test_gen_temporal_output_passes_the_tools_own_warning(monkeypatch, capsys):
    """A secret produced by --gen-temporal must not then be warned about."""
    _run(monkeypatch, ["--gen-temporal"])
    lines = [l.strip() for l in capsys.readouterr().out.splitlines() if l.strip()]
    secret = lines[1].replace("\033[32m", "").replace("\033[0m", "").strip()

    code = _run(monkeypatch, ["testapp", "--ssl", "-T", secret], getpass_inputs=["mymaster"])
    assert code == 0
    assert "147" not in capsys.readouterr().out
