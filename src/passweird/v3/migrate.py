# Passweird v3 - migration from the v2 engine (ADR-0009 §11)
# Licensed under the GNU General Public License v3.0
"""
Reads what v2 left in ~/.passweird and carries the non-secret part of it into
the v3 journal. The v2 engine (passweird.crypto, passweird.storage) is used
here strictly to READ: this module never writes a v2 file.

What can and cannot be carried over:
  - hosts.enc lists contexts in clear once decrypted: each becomes an entry,
    if it has a canonical v3 form. Others are reported, never guessed.
  - the v2 log holds only truncated hashes. It is joined to the hosts list by
    recomputing each context's summary, which recovers the last length and
    character classes used. Records for contexts that are not in the hosts
    list cannot be attributed and are only counted.
  - no password is carried over: v3 derives different ones by design. The old
    and new password of each site can be written to a KDBX file.
  - passwords made with --fido2 cannot be reproduced at all.

A v2 master password that was registered with --register-master, or whose
summary line was ever logged or shown, must be treated as exposed.
"""
import glob
import hashlib
import os

from .. import crypto, storage
from . import app, canon, derive

V2_DIR_FILES = ("master.hash", "hosts.enc", "passweird.log", "fido2.cred")


def v2_dir():
    return os.path.join(os.path.expanduser("~"), ".passweird")


def v2_master_hash(master, keyfile=None):
    try:
        return crypto.modified_hash(master, keyfile_path=os.path.expanduser(keyfile) if keyfile else None)
    except FileNotFoundError as exc:
        raise app.CliError(str(exc)) from None
    except ValueError:
        raise app.CliError("the v2 keyfile does not open with this v2 master password") from None


def read_hosts(master_hash):
    """Contexts from hosts.enc, in file order, or None when there is no file."""
    try:
        content = storage.read_encrypted_hosts(master_hash)
    except ValueError:
        raise app.CliError(
            "hosts.enc does not open with this v2 master password (and keyfile, if one was used)"
        ) from None
    if content is None:
        return None
    return [line.strip() for line in content.splitlines() if line.strip()]


def parse_log(master_hash):
    """Last record per app summary: {summary: {length, feat, temporal, date}}."""
    last, total = {}, 0
    for line in storage.read_logs_from_file(master_hash):
        tokens = line.split()
        fields = {}
        for token in tokens[1:]:
            name, sep, value = token.partition(":")
            if sep:
                fields[name] = value
        if "app" not in fields:
            continue
        total += 1
        last[fields["app"]] = {
            "length": fields.get("len", ""), "feat": fields.get("feat", ""),
            "temporal": fields.get("temporal", ""), "date": tokens[0],
        }
    return last, total


def classes_from_feat(feat):
    """v2 'feat' is lower, upper, digits, specials as four 0/1 characters."""
    if len(feat) != 4 or any(ch not in "01" for ch in feat):
        return None
    return sum(bit for ch, bit in zip(feat, (1, 2, 4, 8)) if ch == "1") or None


def plan(contexts, log):
    """
    Pure planning step: what each v2 context becomes. Returns (items, rejected)
    where an item is a dict ready for the journal plus the v2 parameters needed
    to reproduce the old password.
    """
    items, rejected, seen = [], [], set()
    for context in contexts:
        try:
            site = canon.site(context)
        except canon.CanonicalError as exc:
            rejected.append((context, str(exc)))
            continue
        if site in seen:
            rejected.append((context, f"same canonical site as an earlier line ({site})"))
            continue
        seen.add(site)
        summary = crypto.summarize_hash(crypto.modified_hash(context))
        record = log.get(summary)
        item = {"site": site, "context": context, "length": None, "classes": None,
                "v2_length": 18, "v2_feat": "1111", "v2_temporal": "", "notes": [], "matched": bool(record)}
        if record:
            classes = classes_from_feat(record["feat"])
            try:
                length = int(record["length"])
            except ValueError:
                length = None
            if classes and length:
                item["v2_length"], item["v2_feat"] = length, record["feat"]
                try:
                    item["length"], item["classes"] = canon.length(length, classes), classes
                except canon.CanonicalError:
                    item["classes"] = classes
                    item["notes"].append(f"v2 length {length} is outside the v3 range; default used")
            item["v2_temporal"] = record["temporal"]
            item["date"] = record["date"]
            if record["temporal"]:
                item["notes"].append("v2 password used a temporal secret")
        items.append(item)
    return items, rejected


def v2_password(master_hash, item, temporal=""):
    feat = item["v2_feat"]
    return crypto.generate_password(
        "v2", master_hash, crypto.modified_hash(item["context"]), item["v2_length"],
        temporal_salt=temporal, use_lower=feat[0] == "1", use_upper=feat[1] == "1",
        use_digits=feat[2] == "1", use_special=feat[3] == "1",
    )


def temporal_summary(temporal):
    if not temporal:
        return ""
    return crypto.summarize_hash(hashlib.sha256(temporal.encode()).hexdigest())


def leftover_v2_files():
    directory = v2_dir()
    found = [os.path.join(directory, name) for name in V2_DIR_FILES
             if os.path.isfile(os.path.join(directory, name))]
    found += sorted(glob.glob(os.path.join(directory, "password-*.csv")))
    return found


# --- commands ----------------------------------------------------------------

def cmd_migrate_v2(args, prompter, profile):
    config = app.require_config(profile)
    master_hash = v2_master_hash(prompter.secret("v2 master password"), args.v2_key_file)
    contexts = read_hosts(master_hash)
    if contexts is None:
        app.say("No hosts.enc found: there is no site list to import.")
        contexts = []
    log, log_total = parse_log(master_hash)
    items, rejected = plan(contexts, log)
    matched = {crypto.summarize_hash(crypto.modified_hash(i["context"])) for i in items if i["matched"]}
    unattributed = len(set(log) - matched)

    export = bool(args.export_kdbx)
    temporal = ""
    session = None
    try:
        if export:
            if any(i["v2_temporal"] for i in items):
                temporal = prompter.secret("v2 temporal secret (empty if unknown)")
            app.say("v3 secrets:")
            session = app.open_derivation(config, prompter, config["user_id"], args.key_file)
        book = app.open_journal(profile, config, prompter, session)

        defaults = (config.get("length", app.DEFAULT_LENGTH), config.get("classes", app.DEFAULT_CLASSES))
        imported, present, pairs = 0, 0, []
        for item in items:
            length = item["length"] or defaults[0]
            classes = item["classes"] or defaults[1]
            try:
                length = canon.length(length, classes)
            except canon.CanonicalError:
                length, classes = app.DEFAULT_LENGTH, app.DEFAULT_CLASSES
            existing = book.get(item["site"], "", include_deleted=True)
            if existing is None:
                x = {"origin": "v2", "v2_context": item["context"]}
                if item.get("date"):
                    x["v2_last_used"] = item["date"]
                app.journal_write(lambda: book.put(item["site"], "", 1, length, classes,
                                                   notes="; ".join(item["notes"]), x=x))
                imported += 1
            else:
                present += 1
            if export:
                entry = book.get(item["site"], "", include_deleted=True)
                reproducible = temporal_summary(temporal) == item["v2_temporal"]
                if reproducible:
                    pairs.append(app._kdbx_entry(
                        entry, v2_password(master_hash, item, temporal),
                        title=f"{entry.site} (v2)", extra_note="Password generated by Passweird v2."))
                else:
                    item["notes"].append("v2 password NOT exported: its temporal secret was not given")
                pairs.append(app._kdbx_entry(
                    entry, derive.password(session.prk, entry.site, entry.login, entry.counter,
                                           entry.length, entry.classes),
                    title=f"{entry.site} (v3)", extra_note="Password generated by Passweird v3."))

        # Re-read from disk before anything is deleted.
        book.load()
        missing = [i["site"] for i in items if book.get(i["site"], "", include_deleted=True) is None]
        if missing:
            raise app.CliError("journal verification failed for: " + ", ".join(missing))

        app.say(f"Sites imported: {imported}; already in the journal: {present}; rejected: {len(rejected)}.")
        for context, reason in rejected:
            app.say(f"  not imported: {context!r}: {reason}")
        app.say(f"v2 log: {log_total} record(s); settings recovered for {len(matched)} site(s); "
                f"{unattributed} context(s) in the log are not in the site list and cannot be identified.")
        for item in items:
            for note in item["notes"]:
                app.say(f"  {item['site']}: {note}")
        if os.path.isfile(os.path.join(v2_dir(), "fido2.cred")):
            app.say("Note: v2 passwords generated with --fido2 cannot be reproduced by this migration.")
        if export and pairs:
            app._write_kdbx(args.export_kdbx, prompter, pairs)
    finally:
        if session is not None:
            session.close()

    _offer_cleanup(args, prompter, profile)
    app.say("")
    app.say("Deleting a file does not erase it from an SSD, a snapshot or a backup. If this v2")
    app.say("master password was ever registered with --register-master, or its summary line")
    app.say("was shown or logged, treat it as exposed and do NOT reuse it as the v3 master.")


def _offer_cleanup(args, prompter, profile):
    files = leftover_v2_files()
    if not files:
        return
    app.say("")
    app.say("v2 files still on this device:")
    for path in files:
        app.say(f"  {path}")
    if not profile.is_default:
        # They belong to no profile, and a command acts on the selected
        # profile and on nothing else (ADR-0013 §5).
        app.say(f"They are shared by every profile on this device, so profile '{profile.name}' does not")
        app.say("offer to delete them: delete them from the default profile (its --migrate-v2 offers")
        app.say("it), or by hand. master.hash can generate every v2 password: remove it soon.")
        return
    if args.keep_v2_files:
        app.say("Kept (--keep-v2-files). master.hash can generate every v2 password: remove it soon.")
        return
    answer = prompter.text("Delete these files now? [y/N]").strip().lower()
    if answer not in ("y", "yes", "s", "sim"):
        app.say("Kept. master.hash can generate every v2 password: remove it soon.")
        return
    for path in files:
        try:
            os.unlink(path)
        except OSError as exc:
            app.say(f"  could not delete {path}: {exc}")
    app.say(f"Deleted {len(files)} file(s).")


def cmd_v2_show(args, prompter, profile):
    """Read-only: the password v2 would have generated for a context."""
    context = args.v2_show
    master_hash = v2_master_hash(prompter.secret("v2 master password"), args.v2_key_file)
    temporal = prompter.secret("v2 temporal secret (empty if none)")
    try:
        classes = canon.classes_from_flags(not args.no_lowercase, not args.no_uppercase,
                                           not args.no_numbers, not args.no_specials)
    except canon.CanonicalError as exc:
        raise app.CliError(str(exc)) from None
    item = {
        "context": context, "v2_length": args.length or 18,
        "v2_feat": "".join("1" if classes & bit else "0" for bit in (1, 2, 4, 8)),
    }
    try:
        password = v2_password(master_hash, item, temporal)
    except ValueError as exc:
        raise app.CliError(str(exc)) from None
    app.say(f"v2 context: {context} (taken exactly as typed; v2 did not canonicalise)")
    app.say(f"v2 password: {password}")
    app.say("Read-only: nothing was logged or stored.")
