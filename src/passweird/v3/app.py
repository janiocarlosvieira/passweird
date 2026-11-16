# Passweird v3 - application layer behind the command line (ADR-0009 §12)
# Licensed under the GNU General Public License v3.0
"""
Everything the CLI does, kept apart from argument parsing so that it can be
tested without a terminal.

Three tiers, three prompts (§6):
  access password   -> the journal: sites, counters, notes
  master + boost    -> every password and key
  recovery wrap     -> the journal again, when the access password is lost

Rules this module enforces:
  - no secret is ever read from argv, printed back, or written to disk;
  - the canonical site and the fingerprint are shown before any password;
  - a journal entry's counter, length and classes win over command-line
    flags unless --force is given.
"""
import datetime
import getpass
import json
import os
import sys

from . import artifacts, canon, derive, fileio, journal, kdbx, keys, wordlist

CONFIG_VERSION = 1
DEFAULT_LENGTH = 18
DEFAULT_CLASSES = 15


class CliError(Exception):
    """A failure to report to the user and exit with status 1."""


# --- paths and configuration -------------------------------------------------

def base_dir():
    return os.path.join(os.path.expanduser("~"), ".passweird", "v3")


def config_path():
    return os.path.join(base_dir(), "config")


def recovery_path():
    return os.path.join(base_dir(), "recovery.pw3")


def default_journal_dir():
    return os.path.join(base_dir(), "journal")


def load_config():
    try:
        config = json.loads(fileio.read_bytes(config_path()).decode("utf-8"))
    except FileNotFoundError:
        return None
    except ValueError:
        raise CliError(f"{config_path()} is not valid JSON") from None
    if config.get("alg") != derive.ALG:
        raise CliError(
            f"this installation was initialised for {config.get('alg')!r}; "
            f"this version implements {derive.ALG!r}"
        )
    return config


def save_config(config):
    fileio.ensure_private_dir(os.path.dirname(base_dir()))
    fileio.ensure_private_dir(base_dir())
    fileio.atomic_write(config_path(), json.dumps(config, indent=1, sort_keys=True).encode("utf-8"))


def require_config():
    config = load_config()
    if config is None:
        raise CliError("not initialised on this device: run --init, or --join for an existing journal")
    return config


# --- prompting ---------------------------------------------------------------

class Prompter:
    """
    Reads secrets with getpass, or line by line from stdin with
    --secrets-stdin (for automation and tests). Secrets never come from argv.
    """

    def __init__(self, from_stdin=False, out=None):
        self.from_stdin = from_stdin
        self.out = out or sys.stdout

    def _line(self, label):
        line = sys.stdin.readline()
        if line == "":
            raise CliError(f"--secrets-stdin: no more input when asked for: {label}")
        return line.rstrip("\r\n")

    def secret(self, label):
        if self.from_stdin:
            return self._line(label)
        return getpass.getpass(label + ": ")

    def secret_twice(self, label):
        first = self.secret(label)
        if self.secret("Confirm " + label[0].lower() + label[1:]) != first:
            raise CliError(f"the two entries for '{label}' do not match")
        return first

    def text(self, label):
        if self.from_stdin:
            return self._line(label)
        return input(label + ": ")


def say(*parts):
    print(*parts)


def fail_canonical(function, value):
    try:
        return function(value)
    except canon.CanonicalError as exc:
        raise CliError(str(exc)) from None


# --- opening the tiers -------------------------------------------------------

def open_session(prompter, user_id):
    """Derivation tier. Shows the fingerprint, the only typo check there is."""
    master = prompter.secret("Master password")
    boost = prompter.secret("Boost")
    try:
        session = derive.Session.open(master, boost, user_id)
    except canon.CanonicalError as exc:
        raise CliError(str(exc)) from None
    say(f"Fingerprint: {session.fingerprint}")
    return session


def apply_keyfile(session, path):
    if not path:
        return
    try:
        factor = keys.open_keyfile(fileio.read_bytes(os.path.expanduser(path)), session.prk_none)
    except FileNotFoundError:
        raise CliError(f"keyfile not found: {path}") from None
    except keys.KeyError_ as exc:
        raise CliError(f"keyfile {path}: {exc}") from None
    session.use_keyfile(factor)


def read_keys_file(config):
    path = journal.keys_path(config["journal_dir"])
    try:
        return fileio.read_bytes(path)
    except FileNotFoundError:
        raise CliError(f"{path} not found: has the journal folder finished syncing?") from None


def open_journal(config, prompter, session=None):
    """
    Journal tier. With a session and a local recovery.pw3 (--keep-recovery-file)
    the journal opens from master + boost alone; otherwise the access password
    is asked for.
    """
    data = read_keys_file(config)
    try:
        journal_id = keys.journal_id_of_keys_file(data)
        dek = None
        if session is not None and os.path.exists(recovery_path()):
            try:
                rec_id, dek = keys.open_recovery(fileio.read_bytes(recovery_path()), session.prk_none)
            except keys.WrongSecret:
                raise CliError(
                    "the local recovery file does not open with this master password and boost "
                    "(check the fingerprint above for a typo)"
                ) from None
            if rec_id != journal_id:
                raise CliError("the local recovery file belongs to a different journal")
        if dek is None:
            try:
                _, dek = keys.open_keys_file(data, prompter.secret("Access password"))
            except keys.WrongSecret:
                raise CliError("wrong access password") from None
            except canon.CanonicalError as exc:
                raise CliError(str(exc)) from None
        return journal.Journal(config["journal_dir"], base_dir(), dek, journal_id,
                               bytes.fromhex(config["device_id"]))
    except keys.KeyError_ as exc:
        raise CliError(str(exc)) from None
    except journal.JournalError as exc:
        raise CliError(f"journal error ({exc.code}): {exc}") from None


def journal_write(action):
    try:
        return action()
    except journal.JournalError as exc:
        raise CliError(f"journal error ({exc.code}): {exc}") from None
    except canon.CanonicalError as exc:
        raise CliError(str(exc)) from None


# --- recovery text -----------------------------------------------------------

def print_recovery(blob):
    say("")
    say("=== Recovery text: shown ONCE, not stored on this device ===")
    say("It opens the journal with your master password and boost if the access")
    say("password is lost. Keep it on paper or offline; anyone holding it can test")
    say("guesses of master + boost against it.")
    say("")
    say(keys.recovery_to_text(blob))
    say("")
    try:
        import qrcode
    except ImportError:
        say("(install 'passweird[qr]' to also get a QR code here)")
        return
    code = qrcode.QRCode(border=2)
    code.add_data("".join(keys.recovery_to_text(blob).split()))
    code.make(fit=True)
    code.print_ascii(out=sys.stdout, invert=True)


def store_recovery(blob):
    fileio.atomic_write(recovery_path(), blob)
    say(f"Recovery file kept at {recovery_path()} (--keep-recovery-file).")
    say("With it, this device opens the journal from master + boost alone; it is also")
    say("an offline oracle for them, so keep it off shared and synced folders.")


def read_recovery(prompter, path=None):
    if path:
        try:
            data = fileio.read_bytes(os.path.expanduser(path))
        except FileNotFoundError:
            raise CliError(f"recovery file not found: {path}") from None
        if data[:4] == keys.MAGIC_RECOVERY:
            return data
        text = data.decode("utf-8", errors="replace")
    elif prompter.from_stdin:
        text = prompter.text("Recovery text")
    else:
        say("Paste the recovery text, then an empty line:")
        lines = []
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line)
        text = " ".join(lines)
    try:
        return keys.recovery_from_text(text)
    except keys.KeyError_ as exc:
        raise CliError(str(exc)) from None


# --- commands ----------------------------------------------------------------

def cmd_gen_boost(count):
    try:
        boost, bits = wordlist.generate_boost(count)
    except ValueError as exc:
        raise CliError(str(exc)) from None
    say(f"Boost: {boost}")
    say(f"Entropy: {bits:.1f} bits ({count} words from a list of {len(wordlist.words())})")
    say("Memorise it. It is the same for every site and is never stored: losing it")
    say("loses every password derived with it.")


def _new_access_password(prompter, master_c=None, boost_c=None):
    """
    The access password opens a file that is replicated to every device, so it
    must not be (a respelling of) a derivation secret: that would turn the
    synced journal into an oracle for it.
    """
    access = prompter.secret_twice("Access password")
    access_c = fail_canonical(canon.access_password, access)
    if (master_c is not None and access_c == master_c) or \
            (boost_c is not None and canon.boost(access_c) == boost_c):
        raise CliError("the access password must differ from the master password and from the boost")
    return access


def cmd_init(args, prompter):
    if load_config() is not None:
        raise CliError(f"already initialised ({config_path()}); use --join only on a new device")
    journal_dir = os.path.abspath(os.path.expanduser(args.journal_dir or default_journal_dir()))
    if os.path.exists(journal.keys_path(journal_dir)):
        raise CliError(f"{journal_dir} already holds a journal; use --join to add this device to it")

    user_id = fail_canonical(canon.user_id, args.user_id or prompter.text("User id (e.g. your e-mail)"))
    # Each secret is validated as soon as it is entered, not after all three.
    master_c = fail_canonical(canon.master, prompter.secret_twice("Master password"))
    boost_c = fail_canonical(canon.boost, prompter.secret_twice("Boost"))
    access = _new_access_password(prompter, master_c, boost_c)

    session = derive.Session(derive.stretch(master_c, boost_c, user_id), user_id)
    try:
        journal_id, dek, device_id = keys.new_journal_id(), keys.new_dek(), journal.new_device_id()
        fileio.ensure_private_dir(journal_dir)
        fileio.write_new(journal.keys_path(journal_dir),
                         keys.build_keys_file(journal_id, dek, access, keys.DEFAULT_ACCESS_PARAMS))
        save_config({
            "version": CONFIG_VERSION, "alg": derive.ALG, "user_id": user_id,
            "journal_dir": journal_dir, "device_id": device_id.hex(),
            "length": DEFAULT_LENGTH, "classes": DEFAULT_CLASSES,
        })
        journal.Journal(journal_dir, base_dir(), dek, journal_id, device_id)   # creates streams/
        say(f"Initialised. User id: {user_id}")
        say(f"Journal folder (the one to synchronise): {journal_dir}")
        say(f"Fingerprint: {session.fingerprint}")
        say("Learn this fingerprint: it is shown on every run and is how you notice a typo.")
        blob = keys.build_recovery(journal_id, dek, session.prk_none)
        print_recovery(blob)
        if args.keep_recovery_file:
            store_recovery(blob)
    finally:
        session.close()


def cmd_join(args, prompter):
    if load_config() is not None:
        raise CliError(f"already initialised ({config_path()})")
    journal_dir = os.path.abspath(os.path.expanduser(args.journal_dir or default_journal_dir()))
    config = {
        "version": CONFIG_VERSION, "alg": derive.ALG, "journal_dir": journal_dir,
        "device_id": journal.new_device_id().hex(), "length": DEFAULT_LENGTH, "classes": DEFAULT_CLASSES,
    }
    data = read_keys_file(config)
    config["user_id"] = fail_canonical(
        canon.user_id, args.user_id or prompter.text("User id (the same one used at --init)"))
    try:
        keys.open_keys_file(data, prompter.secret("Access password"))
    except keys.WrongSecret:
        raise CliError("wrong access password") from None
    except (keys.KeyError_, canon.CanonicalError) as exc:
        raise CliError(str(exc)) from None
    save_config(config)
    say(f"This device joined the journal at {journal_dir} as {config['device_id'][:8]}…")
    say("The user id cannot be checked here: confirm the fingerprint on the first derivation.")


def cmd_new_device_id(args, prompter):
    config = require_config()
    old = config["device_id"]
    config["device_id"] = journal.new_device_id().hex()
    save_config(config)
    try:
        os.unlink(os.path.join(base_dir(), "seen"))
    except FileNotFoundError:
        pass
    say(f"New device id {config['device_id'][:8]}… (was {old[:8]}…). The old stream stays readable.")


def _class_mask(args):
    explicit = args.no_lowercase or args.no_uppercase or args.no_numbers or args.no_specials
    try:
        mask = canon.classes_from_flags(not args.no_lowercase, not args.no_uppercase,
                                        not args.no_numbers, not args.no_specials)
    except canon.CanonicalError as exc:
        raise CliError(str(exc)) from None
    return mask, explicit


def _describe(entry):
    return f"counter {entry.counter}, length {entry.length}, classes {entry.classes}"


def warn_conflict(entry):
    if not entry.conflict:
        return
    say("WARNING: this entry was changed on devices that had not seen each other:")
    for candidate in entry.candidates:
        say(f"  device {candidate['device'][:8]}…: counter {candidate['counter']}, "
            f"length {candidate['length']}, classes {candidate['classes']}")
    say("Using the highest counter. Check which password the site accepts (-C N derives")
    say("an earlier one), then run --resolve for this site.")


def cmd_generate(args, prompter):
    config = load_config()
    if config is None and not args.no_journal:
        raise CliError("not initialised: run --init, or use --no-journal with --user-id for a stateless run")
    user_id = args.user_id or (config or {}).get("user_id")
    if not user_id:
        raise CliError("--user-id is required when there is no configuration")
    user_id = fail_canonical(canon.user_id, user_id)

    raw_site = args.site
    if not raw_site:
        raw_site = prompter.secret("Site (hidden)") if args.paranoid else prompter.text("Site")
    site = fail_canonical(canon.site, raw_site)
    login = fail_canonical(canon.login, args.login)
    say(f"Site: {'(hidden)' if args.paranoid else site}" + (f"   Login: {login}" if login else ""))

    mask, mask_explicit = _class_mask(args)
    length_explicit = args.length is not None
    counter_explicit = args.counter is not None
    if counter_explicit and args.bump:
        raise CliError("--counter and --bump cannot be combined")

    session = open_session(prompter, user_id)
    try:
        apply_keyfile(session, args.key_file)
        book = None if args.no_journal else open_journal(config, prompter, session)
        entry = book.get(site, login, include_deleted=True) if book else None

        defaults = config or {}
        length = args.length if length_explicit else defaults.get("length", DEFAULT_LENGTH)
        classes = mask if mask_explicit else defaults.get("classes", DEFAULT_CLASSES)
        counter = 1
        if entry is not None:
            warn_conflict(entry)
            mismatch = []
            if length_explicit and args.length != entry.length:
                mismatch.append(f"length {args.length} (journal: {entry.length})")
            if mask_explicit and mask != entry.classes:
                mismatch.append(f"classes {mask} (journal: {entry.classes})")
            if mismatch and not args.force:
                raise CliError(
                    "flags differ from the journal entry for this site: " + ", ".join(mismatch)
                    + ". Use --force to derive with the flags and record them."
                )
            if not mismatch:
                length, classes = entry.length, entry.classes
            counter = entry.counter
        if counter_explicit:
            counter = args.counter
        try:
            classes = canon.classes(classes)
            length = canon.length(length, classes)
            counter = canon.counter(counter)
        except canon.CanonicalError as exc:
            raise CliError(str(exc)) from None

        artifact = args.totp or args.ssh or args.ssl or args.rsa is not None or args.pgp
        if artifact and args.bump:
            raise CliError("--bump rotates a password; for key material use -C N")

        if artifact:
            say(f"Counter: {counter}")
            _show_artifact(args, session, site, login, counter)
        elif args.bump:
            if counter >= canon.MAX_COUNTER:
                raise CliError("counter is already at its maximum")
            say(f"Current password (counter {counter}): "
                f"{derive.password(session.prk, site, login, counter, length, classes)}")
            counter += 1
            say(f"New password     (counter {counter}): "
                f"{derive.password(session.prk, site, login, counter, length, classes)}")
        else:
            if entry is not None and counter_explicit and counter < entry.counter:
                say(f"Note: the journal is at counter {entry.counter}; deriving counter {counter} as asked.")
            say(f"Counter: {counter}   Length: {length}   Classes: {classes}")
            say(f"Password: {derive.password(session.prk, site, login, counter, length, classes)}")

        if book is not None:
            changed = (
                entry is None or entry.deleted or counter > entry.counter
                or (length, classes) != (entry.length, entry.classes)
            )
            if changed and not (counter_explicit and entry is not None and counter < entry.counter):
                journal_write(lambda: book.put(
                    site, login, counter, length, classes,
                    notes=entry.notes if entry else "", totp=entry.totp if entry else "",
                    keys_=entry.keys if entry else (), x=entry.x if entry else None))
                say("Journal updated.")
    finally:
        session.close()


def _show_artifact(args, session, site, login, counter):
    if args.totp:
        return _show_totp(session, site, login, counter)
    if args.ssh:
        private, public = artifacts.ssh_keypair(session.prk, site, login, counter)
        say("[SSH public key]")
        say(public)
        say("[SSH private key (OpenSSH)]")
        say(private)
        return
    if args.ssl or args.rsa is not None:
        if args.rsa is not None and args.rsa >= 4096:
            say("Deriving RSA primes, this may take a few seconds...")
        try:
            private, certificate = artifacts.tls_certificate(session.prk, site, login, counter, args.rsa)
        except ValueError as exc:
            raise CliError(str(exc)) from None
        say("[Certificate (PEM)]")
        say(certificate)
        say("[Private key (PEM)]")
        say(private)
        return
    from .. import crypto
    try:
        public, private, fingerprint = crypto.export_pgp_key_armored(
            artifacts.pgp_packets(session.prk, site, login, counter))
    except ImportError:
        raise CliError("--pgp needs the optional dependency: pip install 'passweird[pgp]'") from None
    except (OSError, ValueError) as exc:
        raise CliError(f"--pgp needs a working gpg binary: {exc}") from None
    say(f"[OpenPGP fingerprint] {fingerprint}")
    say("[OpenPGP public key]")
    say(public)
    say("[OpenPGP private key]")
    say(private)


def _show_totp(session, site, login, counter):
    secret = derive.totp_secret(session.prk, site, login, counter)
    say(f"TOTP secret (Base32): {secret}")
    try:
        import pyotp
    except ImportError:
        say("(install 'passweird[totp]' to also get the otpauth URI and the current code)")
        return
    totp = pyotp.TOTP(secret)
    say(f"otpauth URI: {totp.provisioning_uri(name=login or site, issuer_name=site)}")
    say(f"Current code: {totp.now()}")


def _resolve_entry(book, raw_site, raw_login, include_deleted=False):
    site = fail_canonical(canon.site, raw_site)
    login = fail_canonical(canon.login, raw_login)
    entry = book.get(site, login, include_deleted=include_deleted)
    if entry is None:
        others = [e.login for e in book.listing() if e.site == site]
        hint = f" (logins on record: {', '.join(repr(o) for o in others)})" if others else ""
        raise CliError(f"no journal entry for {site}" + (f" / {login}" if login else "") + hint)
    return entry


def _stamp(ts):
    return datetime.datetime.fromtimestamp(ts / 1000, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def cmd_list(args, prompter):
    book = open_journal(require_config(), prompter)
    entries = book.listing()
    if not entries:
        say("The journal is empty.")
    for entry in entries:
        flag = "  [CONFLICT]" if entry.conflict else ""
        say(f"{entry.site}" + (f"  ({entry.login})" if entry.login else "") + f"  - {_describe(entry)}{flag}")
    if book.write_blocked:
        say(f"WARNING: {book.write_blocked}")


def cmd_show(args, prompter):
    book = open_journal(require_config(), prompter)
    entry = _resolve_entry(book, args.show, args.login)
    say(f"Site: {entry.site}")
    say(f"Login: {entry.login or '(none)'}")
    say(f"Counter: {entry.counter}   Length: {entry.length}   Classes: {entry.classes}")
    say(f"Notes: {entry.notes or '(none)'}")
    say(f"Second factor: {entry.totp or '(none)'}")
    say("Physical keys: " + (", ".join(entry.keys) if entry.keys else "(none)"))
    for name, value in sorted(entry.x.items()):
        say(f"{name}: {value}")
    say(f"Last change: {_stamp(entry.updated_ts)}   Records: {entry.records}")
    warn_conflict(entry)


def cmd_history(args, prompter):
    book = open_journal(require_config(), prompter)
    site = fail_canonical(canon.site, args.history) if args.history else None
    records = book.history(site)
    if not records:
        say("No records.")
    for r in records:
        who = r["site"] + (f" ({r['login']})" if r["login"] else "")
        detail = (f"counter {r['counter']}, length {r['length']}, classes {r['classes']}"
                  if r["op"] == journal.OP_PUT else "")
        say(f"{_stamp(r['ts'])}  {r['device'][:8]}…  {r['op']:6}  {who}  {detail}".rstrip())


def cmd_edit(args, prompter):
    book = open_journal(require_config(), prompter)
    entry = _resolve_entry(book, args.edit, args.login)
    notes = entry.notes if args.notes is None else args.notes
    totp = entry.totp if args.second_factor is None else args.second_factor
    hw = entry.keys if args.hw_key is None else [k for k in args.hw_key if k]
    journal_write(lambda: book.put(entry.site, entry.login, entry.counter, entry.length, entry.classes,
                                   notes=notes, totp=totp, keys_=hw, x=entry.x))
    say(f"Updated {entry.site}.")


def cmd_resolve(args, prompter):
    book = open_journal(require_config(), prompter)
    entry = _resolve_entry(book, args.resolve, args.login)
    if not entry.conflict:
        say("Nothing to resolve for this entry.")
        return
    counter = args.counter if args.counter is not None else entry.counter
    journal_write(lambda: book.put(entry.site, entry.login, counter, entry.length, entry.classes,
                                   notes=entry.notes, totp=entry.totp, keys_=entry.keys, x=entry.x))
    resolved = book.get(entry.site, entry.login)
    say(f"Resolved {entry.site}: {_describe(resolved)}.")


def cmd_delete(args, prompter):
    book = open_journal(require_config(), prompter)
    entry = _resolve_entry(book, args.delete, args.login)
    journal_write(lambda: book.delete(entry.site, entry.login))
    say(f"Deleted {entry.site}. Its counter ({entry.counter}) is kept as a floor if it is created again.")


def cmd_import_list(args, prompter):
    config = require_config()
    try:
        with open(os.path.expanduser(args.import_list), encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        raise CliError(f"cannot read {args.import_list}: {exc}") from None
    book = open_journal(config, prompter)
    added = skipped = 0
    rejected = []
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        try:
            site = canon.site(parts[0])
            login = canon.login(parts[1] if len(parts) > 1 else "")
        except canon.CanonicalError as exc:
            rejected.append((number, line, str(exc)))
            continue
        if book.get(site, login, include_deleted=True) is not None:
            skipped += 1
            continue
        journal_write(lambda: book.put(site, login, 1, config.get("length", DEFAULT_LENGTH),
                                       config.get("classes", DEFAULT_CLASSES)))
        added += 1
    say(f"Imported {added}, already present {skipped}, rejected {len(rejected)}.")
    for number, line, reason in rejected:
        say(f"  line {number}: {line!r}: {reason}")


def cmd_change_access_password(args, prompter):
    config = require_config()
    data = read_keys_file(config)
    try:
        journal_id, dek = keys.open_keys_file(data, prompter.secret("Current access password"))
    except keys.WrongSecret:
        raise CliError("wrong access password") from None
    except (keys.KeyError_, canon.CanonicalError) as exc:
        raise CliError(str(exc)) from None
    new = _new_access_password(prompter)
    fileio.atomic_write(journal.keys_path(config["journal_dir"]),
                        keys.build_keys_file(journal_id, dek, new, keys.DEFAULT_ACCESS_PARAMS))
    _say_not_revoked()


def _say_not_revoked():
    say("Access password changed.")
    say("NOTE: this does not revoke the old one. The journal key is unchanged, so any")
    say("earlier copy of keys.pw3 (file versioning, backups, a device that has not synced)")
    say("still opens the journal with the old password.")


def cmd_recover(args, prompter):
    """Lost access password: open the journal with master + boost and the
    recovery text, then set a new access password."""
    config = require_config()
    data = read_keys_file(config)
    blob = read_recovery(prompter, args.recovery_file)
    session = open_session(prompter, config["user_id"])
    try:
        try:
            journal_id, dek = keys.open_recovery(blob, session.prk_none)
        except keys.WrongSecret:
            raise CliError("the recovery text does not open with this master password and boost") from None
        except keys.KeyError_ as exc:
            raise CliError(str(exc)) from None
        if journal_id != keys.journal_id_of_keys_file(data):
            raise CliError("the recovery text belongs to a different journal")
        new = _new_access_password(prompter)
        fileio.atomic_write(journal.keys_path(config["journal_dir"]),
                            keys.build_keys_file(journal_id, dek, new, keys.DEFAULT_ACCESS_PARAMS))
        _say_not_revoked()
        if args.keep_recovery_file:
            store_recovery(blob)
    finally:
        session.close()


def cmd_print_recovery(args, prompter):
    config = require_config()
    session = open_session(prompter, config["user_id"])
    try:
        book = open_journal(config, prompter, session)
        blob = keys.build_recovery(book.journal_id, book.dek, session.prk_none)
        print_recovery(blob)
        if args.keep_recovery_file:
            store_recovery(blob)
    finally:
        session.close()


def cmd_gen_keyfile(args, prompter):
    config = load_config()
    user_id = args.user_id or (config or {}).get("user_id")
    if not user_id:
        raise CliError("--user-id is required when there is no configuration")
    path = os.path.abspath(os.path.expanduser(args.gen_keyfile))
    if os.path.lexists(path):
        raise CliError(f"refusing to overwrite {path}")
    session = open_session(prompter, fail_canonical(canon.user_id, user_id))
    try:
        fileio.write_new(path, keys.build_keyfile(session.prk_none))
    finally:
        session.close()
    say(f"Keyfile written to {path}. Use it with --key-file.")
    say("It is a possession factor: copy it to every device and to a backup. Without")
    say("it, passwords derived with it cannot be regenerated.")


def _kdbx_entry(entry, password, title=None, extra_note=""):
    notes = "\n".join(part for part in (entry.notes, extra_note) if part)
    fields = {
        "passweird_alg": derive.ALG, "passweird_site": entry.site, "passweird_counter": entry.counter,
        "passweird_length": entry.length, "passweird_classes": entry.classes,
    }
    if entry.totp:
        fields["second_factor"] = entry.totp
    if entry.keys:
        fields["physical_keys"] = ", ".join(entry.keys)
    return {
        "title": title or entry.site, "username": entry.login, "password": password,
        "url": "https://" + entry.site if "." in entry.site else "", "notes": notes, "fields": fields,
    }


def _write_kdbx(path, prompter, entries):
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.lexists(path):
        raise CliError(f"refusing to overwrite {path}")
    password = prompter.secret_twice("Password for the KDBX file")
    try:
        kdbx.export(path, password, entries)
    except kdbx.KdbxError as exc:
        raise CliError(str(exc)) from None
    say(f"Exported {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} to {path}")
    say(f"KDF: {kdbx.KDF_DESCRIPTION}.")
    say("Next: in KeePassXC open your main database, choose Database -> Merge From")
    say("Database..., select this file, then delete it.")


def cmd_export_kdbx(args, prompter):
    config = require_config()
    session = open_session(prompter, config["user_id"])
    try:
        apply_keyfile(session, args.key_file)
        book = open_journal(config, prompter, session)
        if args.site:
            selected = [_resolve_entry(book, args.site, args.login)]
        else:
            selected = book.listing()
        if not selected:
            raise CliError("the journal has no entries to export")
        for entry in selected:
            warn_conflict(entry)
        entries = [
            _kdbx_entry(e, derive.password(session.prk, e.site, e.login, e.counter, e.length, e.classes))
            for e in selected
        ]
        _write_kdbx(args.export_kdbx, prompter, entries)
    finally:
        session.close()


def cmd_mass_rekey(args, prompter):
    """
    New master password and/or boost: derives the old and the new password for
    every entry into one KDBX file, to be changed at each site. Counters do not
    move; the fingerprint and the recovery text change.
    """
    config = require_config()
    if not args.export_kdbx:
        raise CliError("--mass-rekey needs --export-kdbx FILE for the old/new password pairs")
    say("OLD secrets:")
    old = open_session(prompter, config["user_id"])
    try:
        apply_keyfile(old, args.key_file)
        book = open_journal(config, prompter, old)
        say("NEW secrets:")
        master = prompter.secret_twice("New master password")
        boost = prompter.secret_twice("New boost")
        try:
            new = derive.Session.open(master, boost, config["user_id"])
        except canon.CanonicalError as exc:
            raise CliError(str(exc)) from None
        try:
            say(f"New fingerprint: {new.fingerprint}")
            if args.new_key_file:
                apply_keyfile(new, args.new_key_file)
            entries = []
            for e in book.listing():
                shape = (e.site, e.login, e.counter, e.length, e.classes)
                entries.append(_kdbx_entry(e, derive.password(old.prk, *shape),
                                           title=f"{e.site} (old)", extra_note="Password before the rekey."))
                entries.append(_kdbx_entry(e, derive.password(new.prk, *shape),
                                           title=f"{e.site} (new)", extra_note="Password after the rekey."))
            if not entries:
                raise CliError("the journal has no entries to rekey")
            _write_kdbx(args.export_kdbx, prompter, entries)
            blob = keys.build_recovery(book.journal_id, book.dek, new.prk_none)
            say("")
            say("A NEW recovery text follows, for the new master password and boost.")
            say("WARNING: the recovery text printed before still opens the journal with the")
            say("OLD master password and boost (the journal key did not change). Destroy it.")
            print_recovery(blob)
            if os.path.exists(recovery_path()) or args.keep_recovery_file:
                store_recovery(blob)
        finally:
            new.close()
    finally:
        old.close()
