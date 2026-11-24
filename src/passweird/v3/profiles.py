# Passweird v3 - profiles: several independent installations on one device (ADR-0013)
# Licensed under the GNU General Public License v3.0
"""
A profile is a local state directory: `config`, `seen` and, if kept,
`recovery.pw3`. Its name is only a label. It enters no derivation, no journal
file and no record, so renaming a profile is renaming its directory.

    ~/.passweird/v3/                  profile "default": today's files, unmoved
    ~/.passweird/v3/profiles/<name>/  every other profile

The profile is chosen explicitly every time: --profile, then PASSWEIRD_PROFILE,
then "default". Nothing remembers the last one used. This is the only module
that reads PASSWEIRD_PROFILE.

The checks of §6 live here as well: one profile per journal on a device, and a
journal folder that never holds local state.
"""
import json
import os
import re
from dataclasses import dataclass

from . import canon, fileio, journal, keys

DEFAULT = "default"
ENV_VAR = "PASSWEIRD_PROFILE"
PROFILES_DIRNAME = "profiles"

_NAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?")
NAME_RULE = ("1 to 32 characters from a-z, 0-9 and '-', starting and ending with a "
             "letter or a digit")
# Refused on every platform, so that a name valid on one system is valid on all.
WINDOWS_DEVICE_NAMES = frozenset(
    ["con", "prn", "aux", "nul"] + [f"com{i}" for i in range(1, 10)] + [f"lpt{i}" for i in range(1, 10)]
)


class ProfileError(Exception):
    """A failure to report to the user and exit with status 1."""


def local_state_dir():
    # ADR-0012 §1 will move this to %LOCALAPPDATA% on Windows; until then it is
    # today's directory on every platform.
    return os.path.join(os.path.expanduser("~"), ".passweird", "v3")


def profiles_dir():
    return os.path.join(local_state_dir(), PROFILES_DIRNAME)


def canonical_name(raw):
    """Trimmed and ASCII-lowered, as a user id is (ADR-0009 §1), then checked.
    A name that fails is rejected with the rule, never adjusted."""
    if not isinstance(raw, str):
        raise ProfileError("a profile name must be text")
    name = canon._ascii_lower(canon._trim(raw))
    if not _NAME.fullmatch(name):
        raise ProfileError(f"invalid profile name {raw!r}: use {NAME_RULE}")
    if name in WINDOWS_DEVICE_NAMES:
        raise ProfileError(f"invalid profile name {raw!r}: {name!r} is reserved (a Windows device name)")
    return name


@dataclass(frozen=True)
class Profile:
    name: str
    directory: str

    @property
    def is_default(self):
        return self.name == DEFAULT

    @property
    def config_path(self):
        return os.path.join(self.directory, "config")

    @property
    def recovery_path(self):
        return os.path.join(self.directory, "recovery.pw3")

    @property
    def seen_path(self):
        return os.path.join(self.directory, "seen")

    @property
    def default_journal_dir(self):
        return os.path.join(self.directory, "journal")

    @property
    def prompt_prefix(self):
        return "" if self.is_default else f"[{self.name}] "

    def exists(self):
        """Initialised: it has a configuration."""
        return os.path.isfile(self.config_path)

    def ensure_directory(self):
        """Creates the directory and every parent below ~ with private modes.
        Only --init and --join get here."""
        fileio.ensure_private_dir(os.path.dirname(local_state_dir()))
        fileio.ensure_private_dir(local_state_dir())
        if not self.is_default:
            fileio.ensure_private_dir(profiles_dir())
            fileio.ensure_private_dir(self.directory)
        return self.directory


def profile(name):
    name = canonical_name(name)
    if name == DEFAULT:
        return Profile(DEFAULT, local_state_dir())
    return Profile(name, os.path.join(profiles_dir(), name))


def resolve(cli_value, environ=None):
    """--profile NAME if given, else PASSWEIRD_PROFILE if set and not empty,
    else "default"."""
    environ = os.environ if environ is None else environ
    if cli_value is not None:
        return profile(cli_value)
    from_env = environ.get(ENV_VAR, "")
    if from_env != "":
        return profile(from_env)
    return profile(DEFAULT)


def not_found(prof):
    return ProfileError(
        f"profile '{prof.name}' does not exist on this device. Create it with "
        f"--init --profile {prof.name}, or add this device to an existing journal with "
        f"--join --profile {prof.name}"
    )


# --- listing -----------------------------------------------------------------

def _installed(include_invalid=False):
    """(name, directory) of every directory that holds a config, default first.
    With include_invalid, also directories whose name is not a valid profile
    name (a hand rename): they cannot be selected, but their journals still
    count for the checks of §6."""
    found = []
    if os.path.isfile(os.path.join(local_state_dir(), "config")):
        found.append((DEFAULT, local_state_dir()))
    try:
        names = sorted(os.listdir(profiles_dir()))
    except (FileNotFoundError, NotADirectoryError):
        names = []
    for entry in names:
        directory = os.path.join(profiles_dir(), entry)
        if not os.path.isfile(os.path.join(directory, "config")):
            continue
        try:
            valid = canonical_name(entry) == entry and entry != DEFAULT
        except ProfileError:
            valid = False
        if valid or include_invalid:
            found.append((entry, directory))
    return found


def listing():
    """Every initialised profile that can be selected, "default" first."""
    return [Profile(name, directory) for name, directory in _installed()]


def unselectable():
    """Directories under profiles/ that hold a config but cannot be selected."""
    valid = {directory for _, directory in _installed()}
    return [directory for _, directory in _installed(include_invalid=True) if directory not in valid]


def read_config(directory):
    """The config of a profile directory as a dict, or None if it is missing or
    unreadable. Used only for checks and listings; app.load_config is the
    strict reader."""
    try:
        config = json.loads(fileio.read_bytes(os.path.join(directory, "config")).decode("utf-8"))
    except (OSError, ValueError):
        return None
    return config if isinstance(config, dict) else None


# --- §6: what keeps profiles independent -------------------------------------

def _real(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(path))))


def _is_within(path, ancestor):
    try:
        return os.path.commonpath([path, ancestor]) == ancestor
    except ValueError:              # different drives on Windows
        return False


def check_journal_folder(prof, journal_dir):
    """§6.2: the journal folder of any profile must not be, or contain, the
    local state directory or a profile directory. A synchroniser pointed at it
    would replicate config, seen and any recovery.pw3."""
    folder = _real(journal_dir)
    state = [local_state_dir(), prof.directory] + [d for _, d in _installed(include_invalid=True)]
    for directory in state:
        if _is_within(_real(directory), folder):
            raise ProfileError(
                f"the journal folder {journal_dir} is or contains local state ({directory}). "
                "A journal folder is synchronised and must never hold config, seen or a "
                "recovery file: choose another --journal-dir"
            )


def check_new_profile(prof, journal_dir):
    """
    The checks of §6 that --init and --join run before a profile is created,
    on top of those of every journal open, so that a profile directory made
    later does not land in a journal folder either (§6.2):

    - the journal folder must not be, or lie inside, profiles/, where profile
      directories are created. A named profile's journal may lie inside that
      profile's own directory, as its default journal/ does;
    - the new profile directory must not lie inside the configured journal
      folder of any profile on this device.
    """
    check_journal_folder(prof, journal_dir)
    folder, own = _real(journal_dir), _real(prof.directory)
    in_own_directory = not prof.is_default and folder != own and _is_within(folder, own)
    if _is_within(folder, _real(profiles_dir())) and not in_own_directory:
        raise ProfileError(
            f"the journal folder {journal_dir} is or lies inside {profiles_dir()}, where profile "
            "directories are created: a profile made there would put its local state in a "
            "synchronised folder. Choose another --journal-dir"
        )
    for name, directory in _installed(include_invalid=True):
        config = read_config(directory)
        other = config.get("journal_dir") if config else None
        if isinstance(other, str) and _is_within(own, _real(other)):
            raise ProfileError(
                f"this profile's directory, {prof.directory}, would lie inside the journal folder of "
                f"profile '{name}' ({other}), and a synchroniser would replicate its local state: "
                "config, seen and any recovery file. A profile cannot be created inside a journal folder"
            )


def journal_id_at(journal_dir):
    """The journal_id in the clear header of keys.pw3, or None if the file
    cannot be read. No secret is involved."""
    try:
        return keys.journal_id_of_keys_file(fileio.read_bytes(journal.keys_path(journal_dir)))
    except (OSError, keys.KeyError_):
        return None


def owner_of_journal(prof, journal_id):
    """
    Returns (owner, skipped). `owner` is the name of another profile on this
    device whose journal has this id, or None. `skipped` names the other
    profiles that could not be compared because their keys.pw3 (or config)
    cannot be read now: not synced yet, unmounted, damaged.
    """
    skipped = []
    for name, directory in _installed(include_invalid=True):
        if _real(directory) == _real(prof.directory):
            continue
        config = read_config(directory)
        journal_dir = config.get("journal_dir") if config else None
        other = journal_id_at(journal_dir) if isinstance(journal_dir, str) else None
        if other is None:
            skipped.append(name)
        elif other == journal_id:
            return name, skipped
    return None, skipped


def check_journal_owner(prof, journal_dir, journal_id):
    """§6.1: one profile per journal on a device. Comparing the identifier
    rather than the path also catches a symbolic link or a copy. Returns the
    names of the profiles that could not be compared."""
    owner, skipped = owner_of_journal(prof, journal_id)
    if owner is not None:
        raise ProfileError(
            f"the journal in {journal_dir} is already attached to profile '{owner}' on this device. "
            "A journal belongs to one profile only: use that profile, or another journal"
        )
    return skipped


def profiles_with_user_id(prof, user_id):
    """§6.3: other profiles on this device with the same (canonical) user id."""
    same = []
    for name, directory in _installed(include_invalid=True):
        if _real(directory) == _real(prof.directory):
            continue
        config = read_config(directory)
        if config and config.get("user_id") == user_id:
            same.append(name)
    return same
