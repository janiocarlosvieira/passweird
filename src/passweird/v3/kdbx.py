# Passweird v3 - export to an encrypted KeePass database (ADR-0009 §6)
# Licensed under the GNU General Public License v3.0
"""
Generated passwords leave Passweird only inside a KDBX 4 file. There is no
plaintext exporter.

The KDF of the exported file is set here, explicitly, and read back after
writing. The library's own default comes from a bundled template (Argon2d,
64 MiB, and the template's salt), which is not something to inherit silently.

Intended flow: export to a new file, open the main database in KeePassXC, use
Database -> Merge From Database... on the export, then delete the export.
"""
import os
import uuid

from . import fileio

KDF_ARGON2ID_UUID = uuid.UUID("9e298b19-56db-4773-b23d-fc3ec6f0a1e6").bytes
KDF_MEMORY_BYTES = 256 * 1024 * 1024
KDF_ITERATIONS = 3
KDF_PARALLELISM = 4
KDF_SALT_BYTES = 32
KDF_DESCRIPTION = "Argon2id, 256 MiB, 3 iterations, parallelism 4"


class KdbxError(Exception):
    pass


def _require_pykeepass():
    try:
        import pykeepass
    except ImportError:
        raise KdbxError(
            "KDBX export needs the optional dependency: pip install 'passweird[kdbx]'"
        ) from None
    return pykeepass


def _kdf_parameters(database):
    return database.kdbx.header.value.dynamic_header.kdf_parameters.data.dict


def read_kdf(database):
    """(uuid bytes, memory bytes, iterations, parallelism, salt) as stored."""
    params = _kdf_parameters(database)
    return (bytes(params["$UUID"].value), params["M"].value, params["I"].value,
            params["P"].value, bytes(params["S"].value))


def _set_kdf(database):
    params = _kdf_parameters(database)
    try:
        params["$UUID"].value = KDF_ARGON2ID_UUID
        params["M"].value = KDF_MEMORY_BYTES
        params["I"].value = KDF_ITERATIONS
        params["P"].value = KDF_PARALLELISM
        params["S"].value = os.urandom(KDF_SALT_BYTES)
    except (KeyError, AttributeError) as exc:
        raise KdbxError(f"cannot set the KDF of the KDBX file with this pykeepass version: {exc}") from None


def export(path, password, entries, group_name="Passweird"):
    """
    Writes a new KDBX 4 database at `path` (never overwrites) holding `entries`:
    dicts with title, username, password, url, notes and a `fields` map of
    custom string attributes. Fails rather than write a file with another KDF.
    """
    pykeepass = _require_pykeepass()
    if not password:
        raise KdbxError("the KDBX file needs a password")
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.lexists(path):
        raise KdbxError(f"refusing to overwrite {path}")
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        raise KdbxError(f"directory does not exist: {directory}")

    # Created under a private temporary name, verified, then renamed into place.
    temp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, fileio.FILE_MODE)
    os.close(fd)
    try:
        database = pykeepass.create_database(temp, password=password)
        _set_kdf(database)
        group = database.add_group(database.root_group, group_name)
        for entry in entries:
            added = database.add_entry(
                group, entry["title"], entry.get("username", ""), entry["password"],
                url=entry.get("url") or None, notes=entry.get("notes") or None, force_creation=True,
            )
            for name, value in (entry.get("fields") or {}).items():
                added.set_custom_property(name, str(value))
        database.save()

        reopened = pykeepass.PyKeePass(temp, password=password)
        kdf_uuid, memory, iterations, parallelism, salt = read_kdf(reopened)
        if (kdf_uuid, memory, iterations, parallelism) != (
                KDF_ARGON2ID_UUID, KDF_MEMORY_BYTES, KDF_ITERATIONS, KDF_PARALLELISM) \
                or len(salt) != KDF_SALT_BYTES or reopened.version[0] != 4:
            raise KdbxError("the written KDBX file does not carry the declared KDF; export aborted")
        if len(reopened.entries) != len(entries):
            raise KdbxError("the written KDBX file does not hold every entry; export aborted")
        os.chmod(temp, fileio.FILE_MODE)
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    return path
