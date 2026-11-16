#!/usr/bin/env python3
# main.py
# Passweird - Command Line Interface (v3 engine, ADR-0009)
# Licensed under the GNU General Public License v3.0

import argparse
import sys

from .v3 import app

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
    derivation.add_argument("--key-file", metavar="PATH", help="keyfile to use as a second factor")
    derivation.add_argument("--totp", action="store_true", help="derive a TOTP secret for the site instead")

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
    recovery.add_argument("--new-key-file", metavar="PATH", help="with --mass-rekey: keyfile for the new secrets")

    parser.add_argument("--secrets-stdin", action="store_true",
                        help="read every prompt from standard input, one per line (automation)")
    return parser


def dispatch(args, prompter):
    if args.gen_boost is not None:
        return app.cmd_gen_boost(args.gen_boost)
    if args.init:
        return app.cmd_init(args, prompter)
    if args.join:
        return app.cmd_join(args, prompter)
    if args.new_device_id:
        return app.cmd_new_device_id(args, prompter)
    if args.gen_keyfile:
        return app.cmd_gen_keyfile(args, prompter)
    if args.list:
        return app.cmd_list(args, prompter)
    if args.show:
        return app.cmd_show(args, prompter)
    if args.history is not None:
        return app.cmd_history(args, prompter)
    if args.edit:
        return app.cmd_edit(args, prompter)
    if args.resolve:
        return app.cmd_resolve(args, prompter)
    if args.delete:
        return app.cmd_delete(args, prompter)
    if args.import_list:
        return app.cmd_import_list(args, prompter)
    if args.change_access_password:
        return app.cmd_change_access_password(args, prompter)
    if args.recover:
        return app.cmd_recover(args, prompter)
    if args.print_recovery:
        return app.cmd_print_recovery(args, prompter)
    if args.mass_rekey:
        return app.cmd_mass_rekey(args, prompter)
    if args.export_kdbx:
        return app.cmd_export_kdbx(args, prompter)
    return app.cmd_generate(args, prompter)


def main():
    args = build_parser().parse_args()
    prompter = app.Prompter(from_stdin=args.secrets_stdin)
    try:
        dispatch(args, prompter)
    except app.CliError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        sys.exit(130)
    sys.exit(0)


if __name__ == "__main__":
    main()
