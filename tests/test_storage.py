import csv
import os
from passweird import crypto, storage


import pytest



def test_export_formats_completeness():
    expected = {"bitwarden", "keepassxc", "protonpass", "chrome", "firefox", "seahorse", "kaspersky"}
    assert expected.issubset(storage.EXPORT_FORMATS.keys())
    for fmt, spec in storage.EXPORT_FORMATS.items():
        row = spec["row"]("Name", "https://example.com", "user", "pwd123")
        assert len(row) == len(spec["header"])


def test_settings_roundtrip_restored_keys():
    settings = {
        "length": 24,
        "paranoid": True,
        "no_uppercase": False,
        "no_lowercase": False,
        "no_numbers": False,
        "no_specials": True,
        "change": False,
        "write": True,
        "no_print_hash": True,
        "invisible_password": "blue",
        "file": "~/.passweird/passweird.pwd",
        "temporal_secret_file": "~/.passweird/passweird.temporal",
    }
    storage.save_settings(settings)
    loaded = storage.load_settings()
    for key, value in settings.items():
        assert loaded[key] == value


def test_create_default_config_creates_file(tmp_path):
    config_path = os.path.join(str(tmp_path), "passweird.cfg")
    storage.create_default_config(config_path)
    assert os.path.exists(config_path)
    with open(config_path) as f:
        content = f.read()
    assert "length=18" in content
    assert "temporal_secret_file=" in content


def test_export_to_csv_writes_header_and_row():
    path = storage.export_to_csv("bitwarden", "Site A", "https://a.example", "user", "pwd1")
    assert os.path.exists(path)
    with open(path) as f:
        rows = list(csv.reader(f))
    assert rows[0] == storage.EXPORT_FORMATS["bitwarden"]["header"]
    assert rows[1] == storage.EXPORT_FORMATS["bitwarden"]["row"]("Site A", "https://a.example", "user", "pwd1")


def test_get_export_writer_accumulates_rows():
    writer, handle, path = storage.get_export_writer("bitwarden")
    writer.writerow(storage.EXPORT_FORMATS["bitwarden"]["row"]("Site A", "u1", "user", "pwd1"))
    handle.close()

    writer2, handle2, path2 = storage.get_export_writer("bitwarden", export_file=path)
    writer2.writerow(storage.EXPORT_FORMATS["bitwarden"]["row"]("Site B", "u2", "user", "pwd2"))
    handle2.close()

    assert path == path2
    with open(path) as f:
        lines = f.readlines()
    # header + 2 data rows, header must appear exactly once
    assert len(lines) == 3


def test_build_and_log_line_and_find_in_log_roundtrip():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    app_sum = crypto.summarize_hash(ah)

    line = storage.build_and_log_line(
        "20260731120000", 18, mh, ah, "somePassword1!", "1111",
        temporal_secret="2026/01", print_hash=False,
    )
    assert "temporal:" in line
    assert "'2026/01'" not in line  # must be a hashed summary now, not raw plaintext

    matches = storage.find_in_log(app_sum, "2026/01", mh)
    assert len(matches) == 1
    assert matches[0] == line

    no_matches = storage.find_in_log(app_sum, "2026/02", mh)
    assert no_matches == []


def test_build_and_log_line_includes_keyfile_hash(tmp_path):
    keyfile = tmp_path / "k.bin"
    keyfile.write_bytes(b"some keyfile bytes")
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")

    line = storage.build_and_log_line(
        "20260731120000", 18, mh, ah, "somePassword1!", "1111",
        print_hash=False, keyfile_path=str(keyfile),
    )
    assert " key:" in line


def test_build_and_log_line_respects_log_enabled_and_encrypt_flags():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    storage.build_and_log_line("20260731120000", 18, mh, ah, "pwd", "1111",
                                print_hash=False, log_enabled=False)
    assert storage.read_logs_from_file(mh) == []

    storage.build_and_log_line("20260731120000", 18, mh, ah, "pwd", "1111",
                                print_hash=False, log_enabled=True, encrypt=False)
    records = storage.read_logs_from_file(None)
    assert len(records) == 1


def test_find_last_features_returns_most_recent():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    app_sum = crypto.summarize_hash(ah)

    storage.build_and_log_line("20260731120000", 18, mh, ah, "pwd1", "1111", print_hash=False)
    storage.build_and_log_line("20260731130000", 24, mh, ah, "pwd2", "1010", print_hash=False)

    result = storage.find_last_features(app_sum, mh)
    assert result == (24, "1010")


def test_find_last_features_none_when_no_prior_entry():
    mh = crypto.modified_hash("master")
    assert storage.find_last_features("nonexistent-summary", mh) is None


def test_encrypt_and_read_hosts_roundtrip(tmp_path):
    source = tmp_path / "hosts.txt"
    source.write_text("switch-core-01\nservidor-zabbix\n")
    mh = crypto.modified_hash("master")

    storage.encrypt_and_save_hosts(mh, str(source))
    content = storage.read_encrypted_hosts(mh)
    assert "switch-core-01" in content
    assert "servidor-zabbix" in content

    with pytest.raises(ValueError):
        storage.read_encrypted_hosts(crypto.modified_hash("wrong"))


# --- Temporal secret strength guidance ---------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("", "empty"),
    ("2026/01", "numeric"),
    ("08/2026", "numeric"),
    ("2026-01-15", "numeric"),
    ("12345678901234", "numeric"),
    ("Q2", "short"),
    ("curta", "short"),
    ("abcdefghijk", "short"),          # 11 chars, one short of the threshold
    ("senha curta!", None),            # exactly 12
    ("cavalo bateria grampo correto girassol trombone", None),
])
def test_weak_temporal_secret_reason(value, expected):
    assert storage.weak_temporal_secret_reason(value) == expected


def test_weak_temporal_secret_reason_returns_none_not_strong():
    """
    None means 'not obviously weak', never 'strong'. This phrase is exactly the
    kind a charset-based meter would rate at ~147 bits while a rule-based attack
    reaches it in roughly 40 — the helper must stay silent rather than bless it.
    """
    assert storage.weak_temporal_secret_reason("[mYpAsswordiSaUgustoF26]") is None


# --- Random temporal secret generator ----------------------------------------

def test_generate_temporal_secret_is_random_and_sized():
    a, bits_a, source = storage.generate_temporal_secret(6)
    b, bits_b, _ = storage.generate_temporal_secret(6)
    assert a != b
    assert bits_a == bits_b
    assert source in ("wordlist", "charset")
    if source == "wordlist":
        assert len(a.split()) == 6
    # 6 diceware words are 77.5 bits; any pool we accept must not undershoot that.
    assert bits_a >= 77


def test_generate_temporal_secret_scales_with_word_count():
    _, bits4, _ = storage.generate_temporal_secret(4)
    _, bits8, _ = storage.generate_temporal_secret(8)
    assert bits8 > bits4
    assert abs(bits8 / bits4 - 2.0) < 0.01


def test_generate_temporal_secret_rejects_zero_words():
    with pytest.raises(ValueError):
        storage.generate_temporal_secret(0)


def test_generate_temporal_secret_falls_back_without_wordlist(monkeypatch):
    """No system dictionary must not silently yield a weaker secret."""
    monkeypatch.setattr(storage, "_WORDLIST_PATHS", ())
    secret, bits, source = storage.generate_temporal_secret(6)
    assert source == "charset"
    assert bits >= 77
    assert secret != storage.generate_temporal_secret(6)[0]


@pytest.mark.parametrize("source_paths", [None, ()])
def test_generated_secret_never_trips_the_weakness_check(monkeypatch, source_paths):
    """Whatever the generator produces must satisfy the tool's own guidance."""
    if source_paths is not None:
        monkeypatch.setattr(storage, "_WORDLIST_PATHS", source_paths)
    for _ in range(5):
        secret, _, _ = storage.generate_temporal_secret(6)
        assert storage.weak_temporal_secret_reason(secret) is None


# --- Internationalization consistency -----------------------------------------

def test_all_languages_share_the_same_keys():
    """
    A key present in only some languages does not break anything (_() falls back
    to the English default), but silently degrades the translation — exactly what
    happened when the temporal-secret messages were added only in pt. This test
    turns that silence into a failure.
    """
    languages = storage.TRANSLATIONS
    reference = set(languages["pt"])
    for lang, table in languages.items():
        assert set(table) == reference, (
            f"{lang} diverges: missing {sorted(reference - set(table))}, "
            f"extra {sorted(set(table) - reference)}"
        )


@pytest.mark.parametrize("key", ["gen_temporal_bits", "arg_rsa_invalid"])
def test_format_placeholders_match_across_languages(key):
    """
    A translation that drops or renames a placeholder only blows up when the
    message is actually displayed — mid-operation, for a user of that language.
    """
    import re

    def placeholders(text):
        return (sorted(re.findall(r"\{[^}]*\}", text)), sorted(re.findall(r"%[sd]", text)))

    reference = placeholders(storage.TRANSLATIONS["pt"][key])
    for lang, table in storage.TRANSLATIONS.items():
        assert placeholders(table[key]) == reference, f"{lang} diverges on {key}"


def test_translations_render_without_raising():
    """Every message with a placeholder must actually format, in every language."""
    for lang, table in storage.TRANSLATIONS.items():
        assert table["gen_temporal_bits"].format(92.0, "wordlist")
        assert table["arg_rsa_invalid"] % 2049
