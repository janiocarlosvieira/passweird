# Passweird v3 - append-only journal, one stream per device (ADR-0009 §6-§7)
# Licensed under the GNU General Public License v3.0
"""
The journal remembers what a stateless generator cannot: which sites exist and
which counter, length and classes each one uses, plus free-form notes. It never
holds a password or anything that can derive one.

Layout (the journal directory is what a tool such as Syncthing replicates):

    <journal dir>/keys.pw3
    <journal dir>/streams/<device_id hex>.pw3j      one writer per file

State is the union of all streams, ordered by (ts, device_id, seq) and folded
per (site, login). `fold` is a pure function over decoded records so that the
merge rules can be pinned by vectors independently of any file handling.
"""
import hashlib
import json
import os
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import canon, derive, fileio, keys

MAGIC = b"PW3J"
FORMAT_VERSION = 1
RECORD_VERSION = 1
DEVICE_ID_BYTES = 16
PAD_MULTIPLE = 256
MAX_RECORD_BYTES = 1 << 20
STREAM_SUFFIX = ".pw3j"
HEADER_LEN = len(MAGIC) + 1 + keys.JOURNAL_ID_BYTES + DEVICE_ID_BYTES

OP_PUT = "put"
OP_DELETE = "delete"


class JournalError(Exception):
    """`code` is stable and is what the vectors and the CLI key on."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# --- record plaintext --------------------------------------------------------

def encode_record(record):
    """Canonical JSON, zero-padded to a multiple of 256 bytes so that the
    ciphertext length does not reveal how long a note is."""
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return body + b"\x00" * (-len(body) % PAD_MULTIPLE)


def decode_record(plaintext):
    try:
        record = json.loads(plaintext.rstrip(b"\x00").decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise JournalError("malformed", "record is not valid JSON") from None
    return validate_record(record)


def validate_record(record):
    """Rejects anything the fold could misread. Stored values must already be
    canonical: a record is never 'repaired' on read."""
    if not isinstance(record, dict) or record.get("v") != RECORD_VERSION:
        raise JournalError("malformed", "unsupported record version")
    if record.get("op") not in (OP_PUT, OP_DELETE):
        raise JournalError("malformed", "unknown record operation")
    if isinstance(record.get("ts"), bool) or not isinstance(record.get("ts"), int) or record["ts"] < 0:
        raise JournalError("malformed", "record timestamp is not a non-negative integer")
    try:
        if canon.site(record.get("site")) != record["site"] or canon.login(record.get("login")) != record["login"]:
            raise JournalError("malformed", "record holds a non-canonical site or login")
        if record["op"] == OP_PUT:
            canon.counter(record.get("counter"))
            canon.length(record.get("length"), record.get("classes"))
    except canon.CanonicalError as exc:
        raise JournalError("malformed", f"record field out of range: {exc}") from None
    parents = record.get("parents")
    if not isinstance(parents, list) or not all(
        isinstance(p, list) and len(p) == 2 and isinstance(p[0], str)
        and isinstance(p[1], int) and not isinstance(p[1], bool) for p in parents
    ):
        raise JournalError("malformed", "record parents must be [device_hex, seq] pairs")
    if record["op"] == OP_PUT:
        if not isinstance(record.get("notes", ""), str) or not isinstance(record.get("totp", ""), str):
            raise JournalError("malformed", "notes and totp must be text")
        if not isinstance(record.get("keys", []), list) or not all(isinstance(k, str) for k in record.get("keys", [])):
            raise JournalError("malformed", "keys must be a list of text")
        if not isinstance(record.get("x", {}), dict):
            raise JournalError("malformed", "x must be a map")
    return record


def make_put(ts, site, login, counter, length, classes, parents, notes="", totp="", keys_=(), x=None):
    return validate_record({
        "v": RECORD_VERSION, "ts": ts, "op": OP_PUT, "site": site, "login": login,
        "counter": counter, "length": length, "classes": classes,
        "parents": [list(p) for p in parents],
        "notes": notes, "totp": totp, "keys": list(keys_), "x": dict(x or {}),
    })


def make_delete(ts, site, login, parents):
    return validate_record({
        "v": RECORD_VERSION, "ts": ts, "op": OP_DELETE, "site": site, "login": login,
        "parents": [list(p) for p in parents],
    })


# --- stream encryption -------------------------------------------------------

def stream_key(dek, journal_id, device_id):
    prk = derive.hkdf_extract(journal_id, dek)
    return derive.hkdf_expand(prk, derive.lp("PW3J/stream") + device_id, 32)


def stream_header(journal_id, device_id):
    if len(journal_id) != keys.JOURNAL_ID_BYTES or len(device_id) != DEVICE_ID_BYTES:
        raise JournalError("malformed", "journal id or device id has the wrong length")
    return MAGIC + derive.u8(FORMAT_VERSION) + journal_id + device_id


def seal_record(key, header, seq, plaintext, nonce=None):
    nonce = os.urandom(keys.NONCE_BYTES) if nonce is None else nonce
    sealed = nonce + AESGCM(key).encrypt(nonce, plaintext, header + derive.u64(seq))
    return derive.u32(len(sealed)) + sealed


def build_stream(dek, journal_id, device_id, records, nonces=None):
    """Whole stream file for `records` (plain dicts). Nonces injectable for vectors."""
    header = stream_header(journal_id, device_id)
    key = stream_key(dek, journal_id, device_id)
    out = [header]
    for seq, record in enumerate(records):
        nonce = nonces[seq] if nonces else None
        out.append(seal_record(key, header, seq, encode_record(record), nonce))
    return b"".join(out)


def parse_stream(data, dek, journal_id, device_id):
    """
    Decrypts a stream. A wrong header, a failed tag, a gap or a trailing
    fragment is an error naming the stream and the index - never skipped.
    Writes are atomic (fileio), so none of these can come from a power cut.
    """
    name = device_id.hex()
    header = stream_header(journal_id, device_id)
    if data[:len(MAGIC)] != MAGIC:
        raise JournalError("malformed", f"stream {name}: not a Passweird journal stream")
    if data[:HEADER_LEN] != header:
        raise JournalError("foreign", f"stream {name}: header is for another journal or device")
    key = stream_key(dek, journal_id, device_id)
    aead = AESGCM(key)
    records, pos, seq = [], HEADER_LEN, 0
    while pos < len(data):
        if pos + 4 > len(data):
            raise JournalError("truncated", f"stream {name}: partial length field after record {seq - 1}")
        size = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
        if size < keys.NONCE_BYTES + keys.TAG_BYTES or size > MAX_RECORD_BYTES or pos + size > len(data):
            raise JournalError("truncated", f"stream {name}: record {seq} is truncated or has a bad length")
        sealed = data[pos:pos + size]
        pos += size
        try:
            plaintext = aead.decrypt(sealed[:keys.NONCE_BYTES], sealed[keys.NONCE_BYTES:],
                                     header + derive.u64(seq))
        except InvalidTag:
            raise JournalError("tampered", f"stream {name}: record {seq} failed authentication") from None
        record = decode_record(plaintext)
        record["device"], record["seq"] = name, seq
        records.append(record)
        seq += 1
    return records


# --- merge -------------------------------------------------------------------

@dataclass
class Entry:
    site: str
    login: str
    counter: int
    length: int
    classes: int
    notes: str = ""
    totp: str = ""
    keys: list = field(default_factory=list)
    x: dict = field(default_factory=dict)
    deleted: bool = False
    conflict: bool = False
    heads: list = field(default_factory=list)          # [[device_hex, seq], …]
    candidates: list = field(default_factory=list)     # [{counter,length,classes,device,ts}, …]
    updated_ts: int = 0
    records: int = 0

    def as_dict(self):
        return {
            "site": self.site, "login": self.login, "counter": self.counter,
            "length": self.length, "classes": self.classes, "notes": self.notes,
            "totp": self.totp, "keys": list(self.keys), "x": dict(self.x),
            "deleted": self.deleted, "conflict": self.conflict,
            "heads": [list(h) for h in self.heads], "candidates": list(self.candidates),
        }


def order_key(record):
    return (record["ts"], record["device"], record["seq"])


def fold(records):
    """
    Pure merge of decoded records (each carrying 'device' and 'seq').

    Per (site, login), in (ts, device, seq) order:
      - every field except the counter comes from the last put;
      - the counter is the MAXIMUM over every put ever seen, deletes included,
        so it never decreases and a re-created entry cannot return to a
        password that was already retired;
      - heads are the records nobody lists as a parent; more than one put head
        with different (counter, length, classes) is a conflict.

    Records carry the absolute counter. Two devices that both go 3 -> 4 while
    offline derive the same password, and merge to 4 with nothing to resolve.
    """
    by_entry = {}
    for record in sorted(records, key=order_key):
        by_entry.setdefault((record["site"], record["login"]), []).append(record)

    entries = {}
    for (site, login), group in by_entry.items():
        puts = [r for r in group if r["op"] == OP_PUT]
        if not puts:
            continue  # a delete for something this device never saw created
        referenced = {(p[0], p[1]) for r in group for p in r["parents"]}
        heads = [r for r in group if (r["device"], r["seq"]) not in referenced]
        put_heads = [r for r in heads if r["op"] == OP_PUT]
        shapes = {(r["counter"], r["length"], r["classes"]) for r in put_heads}
        last, last_put = group[-1], puts[-1]
        entries[(site, login)] = Entry(
            site=site, login=login,
            counter=max(r["counter"] for r in puts),
            length=last_put["length"], classes=last_put["classes"],
            notes=last_put.get("notes", ""), totp=last_put.get("totp", ""),
            keys=list(last_put.get("keys", [])), x=dict(last_put.get("x", {})),
            deleted=last["op"] == OP_DELETE,
            conflict=len(shapes) > 1,
            heads=[[r["device"], r["seq"]] for r in heads],
            candidates=[
                {"counter": r["counter"], "length": r["length"], "classes": r["classes"],
                 "device": r["device"], "ts": r["ts"]}
                for r in put_heads
            ] if len(shapes) > 1 else [],
            updated_ts=last["ts"], records=len(group),
        )
    return entries


def next_timestamp(now_ms, records):
    """max(wall clock, 1 + highest ts seen): a record written after seeing
    another always sorts after it, whatever the clocks say."""
    highest = max((r["ts"] for r in records), default=-1)
    return max(now_ms, highest + 1)


def check_integrity(lengths, seen, own=None, own_pending_ok=False):
    """
    Compares stream lengths with the highest counts this device has seen.
    Returns None, or the code that blocks writing ("clone"). Raises on rollback.
    """
    for device, known in seen.items():
        if lengths.get(device, 0) < known:
            raise JournalError(
                "rollback",
                f"stream {device} has {lengths.get(device, 0)} records but {known} were seen before",
            )
    if own is not None and lengths.get(own, 0) > seen.get(own, 0) and not own_pending_ok:
        return "clone"
    return None


# --- files -------------------------------------------------------------------

def _now_ms():
    return int(time.time() * 1000)


class Journal:
    """An opened journal: all streams decrypted, folded, and ready to append."""

    def __init__(self, directory, local_dir, dek, journal_id, device_id, clock=_now_ms):
        self.directory = directory
        self.local_dir = local_dir
        self.dek = bytes(dek)
        self.journal_id = journal_id
        self.device_id = device_id
        self.clock = clock
        self.records = []
        self.entries = {}
        self.write_blocked = None      # None, or a human-readable reason
        self.load()

    # paths
    @property
    def streams_dir(self):
        return os.path.join(self.directory, "streams")

    @property
    def own_path(self):
        return os.path.join(self.streams_dir, self.device_id.hex() + STREAM_SUFFIX)

    @property
    def state_path(self):
        return os.path.join(self.local_dir, "seen")

    def _read_state(self):
        try:
            state = json.loads(fileio.read_bytes(self.state_path).decode("utf-8"))
        except FileNotFoundError:
            return {"journal": self.journal_id.hex(), "seen": {}, "pending": None}
        if state.get("journal") != self.journal_id.hex():
            return {"journal": self.journal_id.hex(), "seen": {}, "pending": None}
        return state

    def _write_state(self, state):
        fileio.atomic_write(self.state_path, json.dumps(state, sort_keys=True).encode("utf-8"))

    def load(self):
        fileio.ensure_private_dir(self.directory)
        fileio.ensure_private_dir(self.streams_dir)
        own = self.device_id.hex()
        records, lengths, raw_own, conflict_files = [], {}, b"", []
        for name in sorted(os.listdir(self.streams_dir)):
            if ".sync-conflict-" in name:
                conflict_files.append(name)
                continue
            if not name.endswith(STREAM_SUFFIX):
                continue
            stem = name[:-len(STREAM_SUFFIX)]
            try:
                device_id = bytes.fromhex(stem)
            except ValueError:
                device_id = b""
            if len(device_id) != DEVICE_ID_BYTES or stem != device_id.hex():
                raise JournalError("malformed", f"unexpected file in streams/: {name}")
            data = fileio.read_bytes(os.path.join(self.streams_dir, name))
            parsed = parse_stream(data, self.dek, self.journal_id, device_id)
            lengths[stem] = len(parsed)
            records.extend(parsed)
            if stem == own:
                raw_own = data

        state = self._read_state()
        pending_ok = bool(state.get("pending")) and hashlib.sha256(raw_own).hexdigest() == state["pending"]
        blocked = check_integrity(lengths, state["seen"], own, pending_ok)

        self.write_blocked = None
        if conflict_files:
            self.write_blocked = (
                "sync-conflict copies exist in streams/ (" + ", ".join(conflict_files) + "): "
                "two installations wrote the same stream. Resolve them, then use --new-device-id."
            )
        elif blocked == "clone":
            self.write_blocked = (
                "this device's stream holds records this installation did not write "
                "(copied or restored install). Use --new-device-id."
            )

        if not self.write_blocked:
            merged = dict(state["seen"])
            merged.update({d: max(n, merged.get(d, 0)) for d, n in lengths.items()})
            if merged != state["seen"] or state.get("pending"):
                self._write_state({"journal": self.journal_id.hex(), "seen": merged, "pending": None})
        self.records = records
        self.entries = fold(records)

    # queries
    def get(self, site, login="", include_deleted=False):
        entry = self.entries.get((site, login))
        if entry is None or (entry.deleted and not include_deleted):
            return None
        return entry

    def listing(self, include_deleted=False):
        return [e for _, e in sorted(self.entries.items()) if include_deleted or not e.deleted]

    def history(self, site=None, login=None):
        out = [r for r in self.records
               if (site is None or r["site"] == site) and (login is None or r["login"] == login)]
        return sorted(out, key=order_key)

    # writes
    def _append(self, record):
        if self.write_blocked:
            raise JournalError("blocked", self.write_blocked)
        seq = sum(1 for r in self.records if r["device"] == self.device_id.hex())
        # A stream append is a rewrite of the whole (small) file: the existing
        # bytes are carried over verbatim, never re-encrypted.
        header = stream_header(self.journal_id, self.device_id)
        try:
            existing = fileio.read_bytes(self.own_path)
        except FileNotFoundError:
            existing = header
        new_data = existing + seal_record(
            stream_key(self.dek, self.journal_id, self.device_id), header, seq, encode_record(record))

        state = self._read_state()
        state["pending"] = hashlib.sha256(new_data).hexdigest()
        self._write_state(state)
        fileio.atomic_write(self.own_path, new_data)
        self.load()

    def _heads(self, site, login):
        entry = self.entries.get((site, login))
        return entry.heads if entry else []

    def put(self, site, login="", counter=1, length=18, classes=15, notes="", totp="", keys_=(), x=None):
        """Writes a full snapshot of the entry. The counter never goes below
        the highest value already recorded for it."""
        site, login = canon.site(site), canon.login(login)
        existing = self.entries.get((site, login))
        if existing is not None:
            counter = max(counter, existing.counter)
        record = make_put(next_timestamp(self.clock(), self.records), site, login, counter, length,
                          classes, self._heads(site, login), notes, totp, keys_, x)
        self._append(record)
        return self.entries[(site, login)]

    def delete(self, site, login=""):
        site, login = canon.site(site), canon.login(login)
        if self.get(site, login) is None:
            raise JournalError("missing", f"no entry for {site}" + (f" / {login}" if login else ""))
        self._append(make_delete(next_timestamp(self.clock(), self.records), site, login,
                                 self._heads(site, login)))


def new_device_id():
    return os.urandom(DEVICE_ID_BYTES)


def keys_path(directory):
    return os.path.join(directory, "keys.pw3")
