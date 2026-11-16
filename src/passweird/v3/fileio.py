# Passweird v3 - atomic, private file writes (ADR-0009 §7)
# Licensed under the GNU General Public License v3.0
"""
Every file v3 writes goes through atomic_write: temp file in the same
directory, fsync, rename over the target, fsync of the directory. A power cut
leaves the old file or the new one, never a partial record - which is what
allows the readers to treat any malformed record as an error.
"""
import os

DIR_MODE = 0o700
FILE_MODE = 0o600


def ensure_private_dir(path):
    os.makedirs(path, mode=DIR_MODE, exist_ok=True)
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        pass  # e.g. a filesystem without POSIX modes; the content is encrypted anyway
    return path


def _temp_name(path):
    # The .syncthing.<name>.tmp shape is what Syncthing uses for its own
    # temporaries and ignores when scanning, so a half-written file is never
    # replicated to the other devices.
    directory, name = os.path.split(path)
    return os.path.join(directory, f".syncthing.{name}.{os.getpid()}.tmp")


def atomic_write(path, data):
    directory = os.path.dirname(path) or "."
    ensure_private_dir(directory)
    temp = _temp_name(path)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return  # Windows cannot open a directory; the rename is still atomic
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def write_new(path, data):
    """Like atomic_write, but refuses to replace an existing file."""
    if os.path.lexists(path):
        raise FileExistsError(f"refusing to overwrite {path}")
    atomic_write(path, data)


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()
