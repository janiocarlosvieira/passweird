#!/usr/bin/env python3
# main.py
# Passweird - Command Line Interface (v3 engine, ADR-0009)
# Licensed under the GNU General Public License v3.0

import argparse
import os
import sys

from .v3 import app, migrate, profiles

EPILOG = """\
secrets are always prompted (hidden) and never accepted as arguments:
  access password   opens the journal: sites, counters, notes
  master + boost    derive every password; nothing on disk can

typical use:
  passweird --gen-boost            draw a boost and memorise it
  passweird --init                 once per person
  passweird --join                 once on each further device
  passweird github.com -u fulano   derive (and remember) a password
  passweird github.com --bump      rotate it
  passweird --list                 needs only the access password

profiles (several independent installations on one device):
  passweird --profile work --init  create the profile "work"
  passweird --list-profiles        list them; needs no secret
  PASSWEIRD_PROFILE=work ...       same as --profile work
  Without either, the profile is "default": the installation in ~/.passweird/v3.
  A named profile lives in ~/.passweird/v3/profiles/NAME. To rename it, rename
  that directory; to delete it, delete the directory (and its journal folder,
  if no other device uses it).
  A profile separates state, not derivation: two profiles with the same user id,
  master and boost derive the same passwords. To keep them apart, give them
  other secrets; a different user id alone protects nothing, it is not secret.
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="passweird",
        description="Passweird: deterministic passwords and keys, regenerable from memory (GPLv3)",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("site", nargs="?", help="site or context, e.g. github.com (a URL is reduced to its host)")

    derivation = parser.add_argument_group("derivation")
    derivation.add_argument("-u", "--login", default="", help="login at the site; part of the derivation")
    derivation.add_argument("-C", "--counter", type=int, default=None, metavar="N",
                            help="derive with this counter instead of the journal's")
    derivation.add_argument("--bump", action="store_true",
                            help="rotate: show the current password and the next one, and record it")
    derivation.add_argument("-L", "--length", type=int, default=None, help="password length (default 18)")
    derivation.add_argument("-U", "--no-uppercase", action="store_true", help="disable uppercase letters")
    derivation.add_argument("-l", "--no-lowercase", action="store_true", help="disable lowercase letters")
    derivation.add_argument("-n", "--no-numbers", action="store_true", help="disable digits")
    derivation.add_argument("-s", "--no-specials", action="store_true", help="disable special characters")
    derivation.add_argument("--force", action="store_true",
                            help="derive with the flags given even if the journal entry differs, and record them")
    derivation.add_argument("-p", "--paranoid", action="store_true", help="prompt for the site hidden")
    derivation.add_argument("--no-journal", action="store_true", help="stateless run: read and write nothing")
    derivation.add_argument("--user-id", help="user id (salt); needed only without a configuration")
    derivation.add_argument("--key-file", metavar="PATH",
                            help="keyfile to use as a second factor (with --init or --join: pin it to the profile)")
    derivation.add_argument("--totp", action="store_true", help="derive a TOTP secret for the site instead")
    derivation.add_argument("--ssh", action="store_true", help="derive an Ed25519 SSH key pair instead")
    derivation.add_argument("--ssl", action="store_true", help="derive a self-signed TLS certificate (Ed25519) instead")
    derivation.add_argument("--rsa", type=int, default=None, metavar="BITS",
                            help="like --ssl with an RSA key of BITS (>= 2048, multiple of 16)")
    derivation.add_argument("--pgp", action="store_true", help="derive an OpenPGP key pair instead")

    setup = parser.add_argument_group("setup")
    setup.add_argument("--gen-boost", nargs="?", type=int, const=5, default=None, metavar="N",
                       help="draw a boost of N words (default 5, minimum 4) and exit")
    setup.add_argument("--init", action="store_true", help="first-time setup: user id, secrets, journal")
    setup.add_argument("--join", action="store_true", help="add this device to an existing (synced) journal")
    setup.add_argument("--journal-dir", metavar="DIR", help="journal folder for --init/--join (the one to sync)")
    setup.add_argument("--new-device-id", action="store_true",
                       help="give this installation a new device id (after a copied or restored install)")
    setup.add_argument("--gen-keyfile", metavar="PATH", help="create a keyfile (never overwrites)")
    setup.add_argument("--keep-recovery-file", action="store_true",
                       help="also store the recovery wrap on this device (default: printed once, not stored)")

    profile = parser.add_argument_group("profiles")
    profile.add_argument("--profile", metavar="NAME",
                         help="profile to act on (default: $PASSWEIRD_PROFILE if set, else 'default')")
    profile.add_argument("--list-profiles", action="store_true",
                         help="list the profiles initialised on this device (needs no secret)")
    profile.add_argument("--pin-key-file", metavar="PATH",
                         help="pin a keyfile to the profile: every derivation then uses it and stops without it")
    profile.add_argument("--unpin-key-file", action="store_true", help="remove the profile's keyfile pin")

    book = parser.add_argument_group("journal (access password only)")
    book.add_argument("--list", action="store_true", help="list sites")
    book.add_argument("--show", metavar="SITE", help="show one entry")
    book.add_argument("--history", nargs="?", const="", default=None, metavar="SITE",
                      help="show every record, or those of one site")
    book.add_argument("--edit", metavar="SITE", help="change notes/second factor/keys of an entry")
    book.add_argument("--notes", help="with --edit: free-form notes")
    book.add_argument("--second-factor", metavar="TEXT", help="with --edit: where the site's TOTP/2FA lives")
    book.add_argument("--hw-key", action="append", metavar="TEXT",
                      help="with --edit: a physical key registered at the site (repeat; replaces the list)")
    book.add_argument("--resolve", metavar="SITE", help="clear a conflict (optionally with -C N)")
    book.add_argument("--delete", metavar="SITE", help="delete an entry (its counter is kept as a floor)")
    book.add_argument("--import-list", metavar="FILE", help="add sites from a text file, one per line")
    book.add_argument("--change-access-password", action="store_true", help="change the access password")

    recovery = parser.add_argument_group("recovery and export (master + boost)")
    recovery.add_argument("--recover", action="store_true",
                          help="lost access password: open the journal with the recovery text and set a new one")
    recovery.add_argument("--recovery-file", metavar="PATH", help="with --recover: read the recovery text from a file")
    recovery.add_argument("--print-recovery", action="store_true", help="issue the recovery text again")
    recovery.add_argument("--export-kdbx", metavar="FILE",
                          help="export passwords (all, or SITE) to a new KeePass database")
    recovery.add_argument("--mass-rekey", action="store_true",
                          help="new master/boost: old and new password of every entry into --export-kdbx FILE")
    recovery.add_argument("--new-key-file", metavar="PATH",
                          help="with --mass-rekey: keyfile for the new secrets (on a pinned profile, the new pin)")
    recovery.add_argument("--drop-key-file", action="store_true",
                          help="with --mass-rekey on a pinned profile: no keyfile for the new secrets; the pin is removed")

    legacy = parser.add_argument_group("migration from v2 (read-only)")
    legacy.add_argument("--migrate-v2", action="store_true",
                        help="import the v2 site list and settings into the journal")
    legacy.add_argument("--v2-show", metavar="CONTEXT",
                        help="show the password v2 generated for a context (honours -L and the class flags)")
    legacy.add_argument("--v2-key-file", metavar="PATH", help="v2 keyfile, if the v2 data was made with one")
    legacy.add_argument("--keep-v2-files", action="store_true",
                        help="with --migrate-v2: do not offer to delete the v2 files")

    parser.add_argument("--secrets-stdin", action="store_true",
                        help="read every prompt from standard input, one per line (automation)")
    return parser


def dispatch(args, prompter, profile):
    # The first four need no existing profile; their order here is the one
    # main() relies on to decide that.
    if args.gen_boost is not None:
        return app.cmd_gen_boost(args.gen_boost)
    if args.list_profiles:
        return app.cmd_list_profiles(args, prompter)
    if args.init:
        return app.cmd_init(args, prompter, profile)
    if args.join:
        return app.cmd_join(args, prompter, profile)
    if args.new_device_id:
        return app.cmd_new_device_id(args, prompter, profile)
    if args.pin_key_file:
        return app.cmd_pin_key_file(args, prompter, profile)
    if args.unpin_key_file:
        return app.cmd_unpin_key_file(args, prompter, profile)
    if args.gen_keyfile:
        return app.cmd_gen_keyfile(args, prompter, profile)
    if args.list:
        return app.cmd_list(args, prompter, profile)
    if args.show:
        return app.cmd_show(args, prompter, profile)
    if args.history is not None:
        return app.cmd_history(args, prompter, profile)
    if args.edit:
        return app.cmd_edit(args, prompter, profile)
    if args.resolve:
        return app.cmd_resolve(args, prompter, profile)
    if args.delete:
        return app.cmd_delete(args, prompter, profile)
    if args.import_list:
        return app.cmd_import_list(args, prompter, profile)
    if args.change_access_password:
        return app.cmd_change_access_password(args, prompter, profile)
    if args.recover:
        return app.cmd_recover(args, prompter, profile)
    if args.print_recovery:
        return app.cmd_print_recovery(args, prompter, profile)
    if args.migrate_v2:
        return migrate.cmd_migrate_v2(args, prompter, profile)
    if args.v2_show:
        return migrate.cmd_v2_show(args, prompter, profile)
    if args.mass_rekey:
        return app.cmd_mass_rekey(args, prompter, profile)
    if args.export_kdbx:
        return app.cmd_export_kdbx(args, prompter, profile)
    return app.cmd_generate(args, prompter, profile)


def run(args):
    """Resolves the profile once (ADR-0013 §4) and runs the command in it.
    PASSWEIRD_PROFILE is read here and in no other module (§7)."""
    profile = profiles.resolve(args.profile, os.environ.get(profiles.ENV_VAR))
    no_profile_needed = args.gen_boost is not None or args.list_profiles
    # Only --init and --join create a profile directory, so a mistyped name
    # never yields an empty profile, nor falls back to a stateless run.
    if not (no_profile_needed or args.init or args.join) and not profile.is_default and not profile.exists():
        raise profiles.not_found(profile)
    if not no_profile_needed and not profile.is_default:
        print(f"Profile: {profile.name}")
    dispatch(args, app.Prompter(from_stdin=args.secrets_stdin, profile=profile), profile)


def main():
    parser = build_parser()
    args = parser.parse_args()
    # Checked before any prompt, so a bad value does not cost a typed secret.
    if args.rsa is not None and (args.rsa < 2048 or args.rsa % 16 != 0):
        parser.error(f"--rsa must be at least 2048 and a multiple of 16 (got {args.rsa})")
    if args.drop_key_file and not args.mass_rekey:
        parser.error("--drop-key-file is used with --mass-rekey")
    try:
        run(args)
    except (app.CliError, profiles.ProfileError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        sys.exit(130)
    sys.exit(0)


if __name__ == "__main__":
    main()
