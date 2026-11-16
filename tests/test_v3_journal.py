# ADR-0009 §6-§7 - key hierarchy, per-device streams, merge and file safety.
import os
import stat
import sys

import pytest

from passweird.v3 import derive, fileio, journal, keys
from v3_support import load

VECTORS = load("journal.json")
DERIVATION = load("derivation.json")
JOURNAL_ID = bytes.fromhex(VECTORS["journal_id_hex"])
DEK = bytes.fromhex(VECTORS["dek_hex"])
PRK_NONE = bytes.fromhex(VECTORS["prk_none_from_fixed_k0_hex"])
SMALL = (1024, 1, 1)
DEV_A, DEV_B, DEV_C = (bytes([b]) * 16 for b in (0xAA, 0xBB, 0xCC))


# --- key hierarchy vectors ---------------------------------------------------

def test_prk_matches_the_derivation_vectors():
    assert bytes(derive.extract(bytes.fromhex(DERIVATION["fixed_k0_hex"]))) == PRK_NONE


@pytest.mark.parametrize("case", VECTORS["access_slot"], ids=lambda c: c["label"])
def test_access_slot_vectors(case):
    data = bytes.fromhex(case["keys_file_hex"])
    assert keys.journal_id_of_keys_file(data) == JOURNAL_ID
    assert keys.open_keys_file(data, case["access_password"]) == (JOURNAL_ID, DEK)
    a = case["argon2"]
    params = (a["memory_kib"], a["time_cost"], a["parallelism"])
    assert int.from_bytes(data[21:25], "big") == a["memory_kib"]
    salt = data[33:65]
    assert keys.access_kek(case["access_password"], salt, params).hex() == case["kek_hex"]
    assert keys.build_keys_file(JOURNAL_ID, DEK, case["access_password"], params, salt, data[65:77]) == data


def test_recovery_vectors():
    blob = bytes.fromhex(VECTORS["recovery"]["blob_hex"])
    assert keys.recovery_kek(PRK_NONE, JOURNAL_ID).hex() == VECTORS["recovery"]["kek_hex"]
    assert keys.open_recovery(blob, PRK_NONE) == (JOURNAL_ID, DEK)
    assert keys.recovery_to_text(blob) == VECTORS["recovery"]["text"]
    assert keys.recovery_from_text(VECTORS["recovery"]["text"]) == blob


def test_keyfile_vectors():
    data = bytes.fromhex(VECTORS["keyfile"]["file_hex"])
    assert keys.keyfile_wrap_key(PRK_NONE).hex() == VECTORS["keyfile"]["wrap_key_hex"]
    assert keys.open_keyfile(data, PRK_NONE).hex() == VECTORS["keyfile"]["factor_hex"]


def test_stream_vectors():
    v = VECTORS["stream"]
    device = bytes.fromhex(v["device_id_hex"])
    assert journal.stream_key(DEK, JOURNAL_ID, device).hex() == v["stream_key_hex"]
    assert [journal.encode_record(r).hex() for r in v["records"]] == v["plaintexts_hex"]
    assert all(len(bytes.fromhex(p)) % 256 == 0 for p in v["plaintexts_hex"])
    data = bytes.fromhex(v["file_hex"])
    assert journal.build_stream(DEK, JOURNAL_ID, device, v["records"],
                                [bytes.fromhex(n) for n in v["nonces_hex"]]) == data
    parsed = journal.parse_stream(data, DEK, JOURNAL_ID, device)
    assert [{k: r[k] for k in r if k not in ("device", "seq")} for r in parsed] == v["records"]
    assert [r["seq"] for r in parsed] == [0, 1, 2]


@pytest.mark.parametrize("case", VECTORS["next_timestamp"], ids=lambda c: f"{c['now_ms']}-{c['highest_seen']}")
def test_next_timestamp_vectors(case):
    records = [] if case["highest_seen"] is None else [{"ts": case["highest_seen"]}]
    assert journal.next_timestamp(case["now_ms"], records) == case["expected"]


@pytest.mark.parametrize("scenario", VECTORS["merge"], ids=lambda s: s["name"])
def test_merge_vectors(scenario):
    records = [dict(r, device=device, seq=seq)
               for device, items in scenario["streams"].items() for seq, r in enumerate(items)]
    folded = journal.fold(records)
    assert [folded[k].as_dict() for k in sorted(folded)] == scenario["expected"]
    # The merge must not depend on the order in which streams are read.
    again = journal.fold(list(reversed(records)))
    assert [again[k].as_dict() for k in sorted(again)] == scenario["expected"]


@pytest.mark.parametrize("case", VECTORS["integrity"], ids=lambda c: c["name"])
def test_integrity_vectors(case):
    try:
        outcome = journal.check_integrity(case["lengths"], case["seen"], case["own"],
                                          case["own_write_pending_matches"]) or "ok"
    except journal.JournalError as exc:
        outcome = exc.code
    assert outcome == case["expected"]


# --- key hierarchy behaviour -------------------------------------------------

def test_wrong_access_password_is_rejected():
    data = keys.build_keys_file(JOURNAL_ID, DEK, "certa", SMALL)
    with pytest.raises(keys.WrongSecret):
        keys.open_keys_file(data, "errada")


def test_changing_the_access_password_keeps_the_dek_and_does_not_revoke():
    old = keys.build_keys_file(JOURNAL_ID, DEK, "antiga", SMALL)
    new = keys.build_keys_file(JOURNAL_ID, DEK, "nova", SMALL)
    assert keys.open_keys_file(new, "nova")[1] == DEK
    # Documented limit (ADR Consequences): an old copy of keys.pw3 still works.
    assert keys.open_keys_file(old, "antiga")[1] == DEK


def test_keys_file_is_bound_to_its_header_and_parameters():
    data = bytearray(keys.build_keys_file(JOURNAL_ID, DEK, "senha", SMALL))
    for position in (5, 28, 40, 70, len(data) - 1):     # journal id, t, salt, nonce, tag
        tampered = bytearray(data)
        tampered[position] ^= 1
        with pytest.raises(keys.KeyError_):
            keys.open_keys_file(bytes(tampered), "senha")


def test_absurd_slot_parameters_are_refused_before_any_allocation():
    data = bytearray(keys.build_keys_file(JOURNAL_ID, DEK, "senha", SMALL))
    data[21:25] = (2**31).to_bytes(4, "big")
    with pytest.raises(keys.MalformedKeyFile):
        keys.open_keys_file(bytes(data), "senha")


def test_recovery_needs_the_derivation_tier():
    blob = keys.build_recovery(JOURNAL_ID, DEK, PRK_NONE)
    with pytest.raises(keys.WrongSecret):
        keys.open_recovery(blob, bytes(64))
    with pytest.raises(keys.MalformedKeyFile):
        keys.open_recovery(blob[:-1], PRK_NONE)
    with pytest.raises(keys.MalformedKeyFile):
        keys.recovery_from_text("not base32 !!! 0189")


def test_recovery_text_survives_retyping():
    blob = keys.build_recovery(JOURNAL_ID, DEK, PRK_NONE)
    text = keys.recovery_to_text(blob)
    assert keys.recovery_from_text(text.lower().replace(" ", "-").replace("\n", "  ")) == blob


def test_keyfile_roundtrip_and_wrong_key():
    data = keys.build_keyfile(PRK_NONE)
    factor = keys.open_keyfile(data, PRK_NONE)
    assert len(factor) == 32 and factor != keys.open_keyfile(keys.build_keyfile(PRK_NONE), PRK_NONE)
    with pytest.raises(keys.WrongSecret):
        keys.open_keyfile(data, bytes(64))


def test_one_kind_of_file_does_not_open_as_another():
    """v2 finding 7: ciphertexts carried no magic or binding."""
    with pytest.raises(keys.KeyError_):
        keys.open_recovery(keys.build_keys_file(JOURNAL_ID, DEK, "senha", SMALL), PRK_NONE)
    with pytest.raises(keys.KeyError_):
        keys.open_keyfile(keys.build_recovery(JOURNAL_ID, DEK, PRK_NONE), PRK_NONE)


# --- streams -----------------------------------------------------------------

def _stream(device=DEV_A, count=3):
    records = [journal.make_put(100 + i, "example.org", "", i + 1, 18, 15,
                                [[device.hex(), i - 1]] if i else []) for i in range(count)]
    return journal.build_stream(DEK, JOURNAL_ID, device, records)


def _record_spans(data):
    spans, pos = [], journal.HEADER_LEN
    while pos < len(data):
        size = int.from_bytes(data[pos:pos + 4], "big")
        spans.append((pos, pos + 4 + size))
        pos += 4 + size
    return spans


def _code(callable_):
    with pytest.raises(journal.JournalError) as info:
        callable_()
    return info.value.code


def test_a_flipped_bit_is_an_error_naming_the_record():
    data = bytearray(_stream())
    start, _ = _record_spans(data)[1]
    data[start + 20] ^= 1
    with pytest.raises(journal.JournalError) as info:
        journal.parse_stream(bytes(data), DEK, JOURNAL_ID, DEV_A)
    assert info.value.code == "tampered" and "record 1" in str(info.value)


def test_records_cannot_be_reordered_or_dropped_from_the_middle():
    data = _stream()
    (a0, a1), (b0, b1), (c0, c1) = _record_spans(data)
    head = data[:journal.HEADER_LEN]
    swapped = head + data[b0:b1] + data[a0:a1] + data[c0:c1]
    dropped = head + data[a0:a1] + data[c0:c1]
    assert _code(lambda: journal.parse_stream(swapped, DEK, JOURNAL_ID, DEV_A)) == "tampered"
    assert _code(lambda: journal.parse_stream(dropped, DEK, JOURNAL_ID, DEV_A)) == "tampered"


def test_a_record_cannot_be_moved_to_another_device_or_journal():
    data = _stream(DEV_A)
    moved = journal.stream_header(JOURNAL_ID, DEV_B) + data[journal.HEADER_LEN:]
    assert _code(lambda: journal.parse_stream(moved, DEK, JOURNAL_ID, DEV_B)) == "tampered"
    assert _code(lambda: journal.parse_stream(data, DEK, bytes(16), DEV_A)) == "foreign"
    assert _code(lambda: journal.parse_stream(data, DEK, JOURNAL_ID, DEV_B)) == "foreign"


@pytest.mark.parametrize("cut", [1, 3, 5, 40])
def test_a_partial_record_is_an_error_not_something_to_skip(cut):
    data = _stream()
    assert _code(lambda: journal.parse_stream(data[:-cut], DEK, JOURNAL_ID, DEV_A)) == "truncated"


def test_wrong_dek_fails_on_the_first_record():
    assert _code(lambda: journal.parse_stream(_stream(), bytes(32), JOURNAL_ID, DEV_A)) == "tampered"


def test_non_canonical_or_out_of_range_records_are_rejected():
    good = journal.make_put(1, "example.org", "", 1, 18, 15, [])
    for change in ({"site": "Example.org"}, {"site": "bücher.de"}, {"counter": 0}, {"length": 7},
                   {"classes": 0}, {"v": 2}, {"op": "bump"}, {"ts": -1}, {"parents": [["aa"]]},
                   {"notes": 5}, {"keys": "yubikey"}):
        with pytest.raises(journal.JournalError):
            journal.validate_record({**good, **change})


# --- the journal on disk -----------------------------------------------------

class Clock:
    def __init__(self, now=1_000_000):
        self.now = now

    def __call__(self):
        self.now += 10
        return self.now


@pytest.fixture
def shared(tmp_path):
    """One journal directory (what the sync tool replicates), local dirs apart."""
    def open_as(device, clock=None):
        local = tmp_path / ("local-" + device.hex()[:2])
        return journal.Journal(str(tmp_path / "journal"), str(local), DEK, JOURNAL_ID, device,
                               clock or Clock())
    return open_as


def test_put_get_bump_delete(shared):
    j = shared(DEV_A)
    assert j.listing() == []
    j.put("github.com", notes="pessoal", totp="Aegis", keys_=["YubiKey azul"], x={"cor": "azul"})
    entry = j.get("github.com")
    assert (entry.counter, entry.length, entry.classes, entry.notes, entry.totp, entry.keys, entry.x) == \
        (1, 18, 15, "pessoal", "Aegis", ["YubiKey azul"], {"cor": "azul"})
    j.put("github.com", counter=2, notes="pessoal")
    assert j.get("github.com").counter == 2 and j.get("github.com").heads == [[DEV_A.hex(), 1]]
    j.delete("github.com")
    assert j.get("github.com") is None
    assert j.get("github.com", include_deleted=True).counter == 2
    with pytest.raises(journal.JournalError):
        j.delete("github.com")


def test_state_survives_reopening(shared):
    shared(DEV_A).put("github.com", counter=3)
    assert shared(DEV_A).get("github.com").counter == 3


def test_the_counter_never_goes_down(shared):
    j = shared(DEV_A)
    j.put("github.com", counter=5)
    j.put("github.com", counter=2)
    assert j.get("github.com").counter == 5
    j.delete("github.com")
    j.put("github.com", counter=1)
    assert j.get("github.com").counter == 5


def test_two_devices_merge_through_the_shared_directory(shared):
    a = shared(DEV_A)
    a.put("github.com", counter=3)
    b = shared(DEV_B)                      # B sees A's record
    assert b.get("github.com").counter == 3
    a.put("github.com", counter=4)         # both bump while "offline": neither reloads
    b.put("github.com", counter=4)
    merged = shared(DEV_C)
    entry = merged.get("github.com")
    assert entry.counter == 4 and not entry.conflict and len(entry.heads) == 2


def test_divergent_bumps_conflict_until_a_device_resolves(shared):
    a = shared(DEV_A)
    a.put("github.com", counter=3)
    b = shared(DEV_B)
    a.put("github.com", counter=4)
    a.put("github.com", counter=5)
    b.put("github.com", counter=4)
    c = shared(DEV_C)
    entry = c.get("github.com")
    assert entry.conflict and entry.counter == 5
    assert sorted(x["counter"] for x in entry.candidates) == [4, 5]
    c.put("github.com", counter=entry.counter)     # lists both heads
    assert not shared(DEV_A).get("github.com").conflict


def test_a_slow_clock_cannot_sort_before_what_it_has_seen(shared):
    shared(DEV_A, Clock(5_000_000)).put("github.com", notes="de A")
    b = shared(DEV_B, Clock(10))            # B's wall clock is far behind
    b.put("github.com", notes="de B, depois")
    assert shared(DEV_C).get("github.com").notes == "de B, depois"


def test_each_device_writes_only_its_own_stream(shared, tmp_path):
    shared(DEV_A).put("a.example")
    shared(DEV_B).put("b.example")
    names = sorted(os.listdir(tmp_path / "journal" / "streams"))
    assert names == [DEV_A.hex() + ".pw3j", DEV_B.hex() + ".pw3j"]
    before = (tmp_path / "journal" / "streams" / names[0]).read_bytes()
    shared(DEV_B).put("c.example")
    assert (tmp_path / "journal" / "streams" / names[0]).read_bytes() == before


def test_rollback_of_a_stream_is_detected(shared, tmp_path):
    a = shared(DEV_A)
    a.put("a.example")
    path = tmp_path / "journal" / "streams" / (DEV_A.hex() + ".pw3j")
    one_record = path.read_bytes()
    a.put("b.example")
    b = shared(DEV_B)                      # B has now seen two records from A
    assert len(b.listing()) == 2
    path.write_bytes(one_record)           # an older copy comes back
    assert _code(lambda: shared(DEV_B)) == "rollback"


def test_a_cloned_install_is_refused_writes(shared, tmp_path):
    a = shared(DEV_A)
    a.put("a.example")
    # Another installation with the same device id appends to the same stream.
    clone = journal.Journal(str(tmp_path / "journal"), str(tmp_path / "local-clone"), DEK, JOURNAL_ID,
                            DEV_A, Clock())
    assert clone.write_blocked and "new-device-id" in clone.write_blocked    # stream it never wrote
    (tmp_path / "local-clone" / "seen").unlink(missing_ok=True)
    original = shared(DEV_A)
    assert original.write_blocked is None
    original.put("b.example")
    assert shared(DEV_A).get("b.example") is not None


def test_sync_conflict_copies_block_writing_but_not_reading(shared, tmp_path):
    a = shared(DEV_A)
    a.put("a.example")
    streams = tmp_path / "journal" / "streams"
    (streams / (DEV_A.hex() + ".sync-conflict-20261116-101500-ABCDEFG.pw3j")).write_bytes(b"x")
    again = shared(DEV_A)
    assert again.get("a.example") is not None
    assert _code(lambda: again.put("b.example")) == "blocked"


def test_an_unexpected_file_in_streams_is_an_error(shared, tmp_path):
    shared(DEV_A).put("a.example")
    (tmp_path / "journal" / "streams" / "notes.pw3j").write_bytes(b"x")
    assert _code(lambda: shared(DEV_A)) == "malformed"


def test_interrupted_write_is_recovered_not_mistaken_for_a_clone(shared, tmp_path, monkeypatch):
    j = shared(DEV_A)
    j.put("a.example")
    real_load = journal.Journal.load

    def crash_after_stream_write(self):
        raise RuntimeError("power cut before the local state was committed")

    monkeypatch.setattr(journal.Journal, "load", crash_after_stream_write)
    with pytest.raises(RuntimeError):
        j.put("b.example")
    monkeypatch.setattr(journal.Journal, "load", real_load)
    reopened = shared(DEV_A)
    assert reopened.write_blocked is None and reopened.get("b.example") is not None
    reopened.put("c.example")


# --- atomic writes -----------------------------------------------------------

def test_power_cut_before_rename_leaves_the_old_file(tmp_path, monkeypatch):
    target = tmp_path / "d" / "file"
    fileio.atomic_write(str(target), b"old")

    def boom(src, dst):
        raise OSError("power cut")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        fileio.atomic_write(str(target), b"new content that must not appear")
    monkeypatch.undo()
    assert target.read_bytes() == b"old"
    assert os.listdir(tmp_path / "d") == ["file"]          # no temporary left behind


def test_failed_stream_append_leaves_the_stream_readable(shared, tmp_path, monkeypatch):
    j = shared(DEV_A)
    j.put("a.example")
    real_replace = os.replace

    def fail_on_stream(src, dst):
        if dst.endswith(".pw3j"):
            raise OSError("power cut")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", fail_on_stream)
    with pytest.raises(OSError):
        j.put("b.example")
    monkeypatch.undo()
    reopened = shared(DEV_A)
    assert [e.site for e in reopened.listing()] == ["a.example"]
    reopened.put("b.example")
    assert len(shared(DEV_A).listing()) == 2


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_files_and_directories_are_private(shared, tmp_path):
    shared(DEV_A).put("a.example")
    for root, dirs, files in os.walk(tmp_path / "journal"):
        assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
        for name in files:
            assert stat.S_IMODE(os.stat(os.path.join(root, name)).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "local-aa" / "seen").st_mode) == 0o600


def test_write_new_refuses_to_overwrite(tmp_path):
    path = str(tmp_path / "keyfile")
    fileio.write_new(path, b"first")
    with pytest.raises(FileExistsError):
        fileio.write_new(path, b"second")
    assert fileio.read_bytes(path) == b"first"
