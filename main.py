#!/usr/bin/env python3
# main.py
# Passweird - Command Line Interface (Fully Internationalized)
# Licensed under the GNU General Public License v3.0

import argparse
import csv
import getpass
import hashlib
import os
import sys
import tempfile
from datetime import datetime

import crypto
import storage
from storage import _

ANSI_COLORS = {
    "black": "\033[30m", "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m", "white": "\033[37m",
    "reset": "\033[0m"
}

def prompt_entry_info():
    print(f"{ANSI_COLORS['cyan']}{_('export_prompt_title', '-- Export Manager Entry Information --')}{ANSI_COLORS['reset']}")
    name = input(_('export_title', "Site Title/Description: ")).strip()
    url = input(_('export_url', "Site URL: ")).strip()
    username = input(_('export_user', "Username (Login): ")).strip()
    return name, url, username

def get_master_password(args, prompt=None):
    """Precedence: --master-pass > --master-file > interactive getpass."""
    prompt = prompt or _('master_prompt', "Master password: ")
    if args.master_pass:
        storage.print_command_line_warning()
        return args.master_pass
    elif args.master_file:
        try:
            return storage.read_master_password_file(args.master_file)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}Error reading master password file: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)
    else:
        return getpass.getpass(prompt)

def get_temporal_secret(args):
    """Precedence: -T/--temporal (CLI) > --temporal-secret-file > interactive input."""
    if args.temporal is not None:
        return args.temporal
    elif args.temporal_secret_file:
        candidate = storage.read_temporal_secret_file(args.temporal_secret_file)
        if candidate is None:
            candidate = ''
        return storage.prompt_temporal_secret(candidate)
    else:
        return input(_('temporal_prompt_none', "Temporal secret (third secret) [none]: ")).strip()

def warn_temporal_strength(temporal_secret, publishes_context=False):
    """
    Warns before generating published key material under an obviously guessable
    temporal secret. Only the asymmetric pipelines call this: a weak temporal
    secret on a normal password is bounded by the service's rate limiting, while
    a published public key is an offline oracle with no limit at all.
    """
    reason = storage.weak_temporal_secret_reason(temporal_secret)
    if reason is None:
        return

    if reason == 'empty':
        msg = _('temporal_weak_empty',
                "WARNING: no temporal secret. Your master password becomes the only secret "
                "protecting this published key.")
    elif reason == 'numeric':
        msg = _('temporal_weak_numeric',
                "WARNING: a date-like temporal secret ('2026/01', '08/2026') adds almost no "
                "entropy - such values are exhausted in seconds.")
    else:
        msg = _('temporal_weak_short',
                "WARNING: very short temporal secret. Length alone is not strength, but under "
                "12 characters there is no room for any.")

    hint = _('temporal_weak_hint',
             "Prefer 6+ randomly chosen words (~78 bits, and that figure holds even if the "
             "attacker knows the method). Beware of clever-looking phrases: a strength meter "
             "would rate '[mYpAsswordiSaUgustoF26]' at ~147 bits, while a rule-based attack "
             "reaches it in around 40. See docs/adr/0003 and the README.")

    print(f"{ANSI_COLORS['yellow']}{msg}{ANSI_COLORS['reset']}")
    if publishes_context:
        print(f"{ANSI_COLORS['yellow']}{_('temporal_weak_cn', 'The context name is published with this artifact (certificate CN / PGP UID), so it adds no entropy here either.')}{ANSI_COLORS['reset']}")
    print(f"{ANSI_COLORS['yellow']}{hint}{ANSI_COLORS['reset']}")

def build_parser(cfg):
    parser = argparse.ArgumentParser(description=_('cli_desc', "Passweird: Universal Identity Suite (GPLv3)"))
    parser.add_argument('app_name', nargs='?', help=_('arg_app', 'Name of the application/context (visible mode)'))
    parser.add_argument('-V', '--version', choices=['v2'], default='v2', help=_('arg_ver', 'Algorithm version (Default: v2 HKDF)'))
    parser.add_argument('-T', '--temporal', type=str, default=None, help=_('arg_temp', 'Temporal salt/key version (e.g., 2026/01) - use a strong passphrase with --ssl/--rsa/--pgp'))
    parser.add_argument('-L', '--length', type=int, default=cfg.get('length', 18), help=_('arg_len', 'Password length'))
    parser.add_argument('-p', '--paranoid', action='store_true', default=cfg.get('paranoid', False), help=_('arg_para', 'Paranoid mode: hide app name input'))
    parser.add_argument('-U', '--no-uppercase', action='store_true', default=cfg.get('no_uppercase', False), help=_('arg_upper', 'Disable uppercase letters'))
    parser.add_argument('-l', '--no-lowercase', action='store_true', default=cfg.get('no_lowercase', False), help=_('arg_lower', 'Disable lowercase letters'))
    parser.add_argument('-n', '--no-numbers', action='store_true', default=cfg.get('no_numbers', False), help=_('arg_num', 'Disable numbers'))
    parser.add_argument('-s', '--no-specials', action='store_true', default=cfg.get('no_specials', False), help=_('arg_spec', 'Disable special characters'))
    parser.add_argument('--register-master', action='store_true', help=_('arg_reg', 'Register current master password hash as local machine default'))
    parser.add_argument('--no-check', action='store_true', help=_('arg_nocheck', 'Skip master password verification checkpoint'))
    parser.add_argument('--audit', action='store_true', help=_('arg_audit', 'Audit mode: verify if credentials exist in local log history'))
    parser.add_argument('--save-settings', action='store_true', help=_('arg_save', 'Save current flags as default user preferences'))
    parser.add_argument('-o', '--output', choices=storage.EXPORT_FORMATS.keys(), help=_('arg_out', 'Export directly to manager CSV format'))
    parser.add_argument('--force', action='store_true', help=_('arg_force', 'Skip the last-used-flags mismatch confirmation prompt'))

    # Config / logging control
    parser.add_argument('-g', '--generate', action='store_true', help=_('arg_generate', 'Create a default, commented config file and exit'))
    parser.add_argument('--no-print-hash', action='store_true', default=cfg.get('no_print_hash', False), help=_('arg_no_print_hash', 'Do not print the hash-summary line to the terminal'))
    parser.add_argument('-w', '--write', action='store_true', default=cfg.get('write', False), help=_('arg_write', 'Disable writing hash summaries to the log'))
    parser.add_argument('-v', '--invisible-password', nargs='?', const='black', default=cfg.get('invisible_password') or None, help=_('arg_invisible', 'Print the password using an invisible/matching terminal color'))

    # Master password / temporal secret alternate inputs
    parser.add_argument('--master-file', type=str, help=_('arg_master_file', 'Read the master password from a plaintext file (INSECURE)'))
    parser.add_argument('--master-pass', type=str, help=_('arg_master_pass', 'Pass the master password directly on the CLI (INSECURE)'))
    parser.add_argument('--temporal-secret-file', type=str, default=cfg.get('temporal_secret_file') or None, help=_('arg_temporal_file', 'Read the temporal secret from a file'))
    parser.add_argument('--gen-temporal', nargs='?', type=int, const=6, default=None, metavar='N', help=_('arg_gen_temporal', 'Draw a random temporal secret of N words (default 6) and report its entropy'))

    # Change mode / batch mode / mass rekey
    parser.add_argument('-c', '--change', action='store_true', default=cfg.get('change', False), help=_('arg_change', 'Change mode: generate an old/new password pair'))
    parser.add_argument('-f', '--file', nargs='?', const=cfg.get('file', '~/.passweird/passweird.pwd'), default=None, help=_('arg_file', 'Batch-process a plain text or CSV file of contexts'))
    parser.add_argument('--mass-rekey', action='store_true', help=_('arg_mass_rekey', 'Regenerate passwords for every context in the hosts list under a new master password'))
    parser.add_argument('--old-key-file', type=str, help=_('arg_old_keyfile', 'Old physical keyfile to use during --mass-rekey'))
    parser.add_argument('--new-key-file', type=str, help=_('arg_new_keyfile', 'New physical keyfile to use during --mass-rekey'))

    # Infrastructure & Data Management Flags
    parser.add_argument('--ssh', action='store_true', help=_('arg_ssh', 'Generate deterministic SSH Ed25519 Keys'))
    parser.add_argument('--ssl', action='store_true', help=_('arg_ssl', 'Generate deterministic SSL/TLS Certificates'))
    parser.add_argument('--rsa', type=int, help=_('arg_rsa', 'Specify generation SSL using RSA and define size of bits'))
    parser.add_argument('--totp', action='store_true', help=_('arg_totp', 'Generate a deterministic TOTP secret'))
    parser.add_argument('--pgp', action='store_true', help=_('arg_pgp', 'Generate a deterministic PGP/OpenPGP key pair'))
    parser.add_argument('--encrypt-list', type=str, help=_('arg_encrypt_list', 'Encrypt a plain text file containing hosts/systems'))
    parser.add_argument('--view-list', action='store_true', help=_('arg_view_list', 'Decrypt and display saved hosts/systems list'))
    parser.add_argument('--view-log', action='store_true', help=_('arg_view_log', 'Decrypt and display whole local history log'))
    parser.add_argument('--plain-log', action='store_true', help=_('arg_plain_log', 'Disable standard AES encryption for history logs'))
    parser.add_argument('--key-file', type=str, help=_('arg_keyfile', 'Path to a physical key file as secondary factor'))
    parser.add_argument('--gen-keyfile', type=str, help=_('arg_gen_keyfile', 'Generate a new external keyfile at PATH (see --recoverable)'))
    parser.add_argument('--recoverable', action='store_true', help=_('arg_recoverable', 'With --gen-keyfile: derive it from master password + a recovery phrase instead of pure randomness'))
    parser.add_argument('--fido2-register', action='store_true', help=_('arg_fido2_register', 'Register a new FIDO2 security key credential'))
    parser.add_argument('--fido2', action='store_true', help=_('arg_fido2', 'Use the registered FIDO2 security key as an additional factor'))

    return parser

def run_change_mode(args):
    old_master = get_master_password(args, prompt=_('old_master_prompt', "Old master password: "))
    new_master = getpass.getpass(_('new_master_prompt', "New master password (press Enter to repeat old): "))
    if not new_master:
        new_master = old_master
    old_app = getpass.getpass(_('old_app_prompt', "Old application password: "))
    new_app = getpass.getpass(_('new_app_prompt', "New application password (press Enter to repeat old): "))
    if not new_app:
        new_app = old_app

    old_master_hash = crypto.modified_hash(old_master)
    new_master_hash = crypto.modified_hash(new_master)
    old_app_hash = crypto.modified_hash(old_app)
    new_app_hash = crypto.modified_hash(new_app)

    temporal_old = get_temporal_secret(args)
    temporal_new = storage.prompt_temporal_secret(temporal_old)

    use_lower, use_upper = not args.no_lowercase, not args.no_uppercase
    use_digits, use_special = not args.no_numbers, not args.no_specials
    feat_bin = f"{int(use_lower)}{int(use_upper)}{int(use_digits)}{int(use_special)}"
    date_str = datetime.now().strftime("%Y%m%d%H%M%S")

    try:
        old_pwd = crypto.generate_password('v2', old_master_hash, old_app_hash, args.length,
                                            temporal_salt=temporal_old, use_upper=use_upper,
                                            use_lower=use_lower, use_digits=use_digits, use_special=use_special)
        new_pwd = crypto.generate_password('v2', new_master_hash, new_app_hash, args.length,
                                            temporal_salt=temporal_new, use_upper=use_upper,
                                            use_lower=use_lower, use_digits=use_digits, use_special=use_special)
    except Exception as e:
        print(f"{ANSI_COLORS['red']}Error during password change: {e}{ANSI_COLORS['reset']}")
        return

    print(f"{_('old_pwd', 'Old password: ')}{ANSI_COLORS['yellow']}{old_pwd}{ANSI_COLORS['reset']}")
    print(f"{_('new_pwd', 'New password: ')}{ANSI_COLORS['green']}{new_pwd}{ANSI_COLORS['reset']}\n")

    export_handle = None
    if args.output:
        writer, export_handle, export_file = storage.get_export_writer(args.output)
        print(_('please_old_entry', 'Please enter info for the OLD password entry:'))
        name, url, username = prompt_entry_info()
        writer.writerow(storage.EXPORT_FORMATS[args.output]["row"](name, url, username, old_pwd))
        print(_('please_new_entry', 'Please enter info for the NEW password entry:'))
        name, url, username = prompt_entry_info()
        writer.writerow(storage.EXPORT_FORMATS[args.output]["row"](name, url, username, new_pwd))
        export_handle.close()
        print(f"{ANSI_COLORS['green']}{_('export_success', 'File successfully exported to: ')}{export_file}{ANSI_COLORS['reset']}")

    log_enabled, print_hash, encrypt_log = not args.write, not args.no_print_hash, not args.plain_log
    storage.build_and_log_line(date_str, args.length, old_master_hash, old_app_hash, old_pwd, feat_bin,
                                temporal_secret=temporal_old, change_mode=True,
                                log_enabled=log_enabled, print_hash=print_hash, encrypt=encrypt_log)
    storage.build_and_log_line(date_str, args.length, new_master_hash, new_app_hash, new_pwd, feat_bin,
                                temporal_secret=temporal_new, change_mode=True,
                                log_enabled=log_enabled, print_hash=print_hash, encrypt=encrypt_log)

def run_batch_mode(args):
    master_password = get_master_password(args)
    keyfile_path = os.path.expanduser(args.key_file) if args.key_file else None
    try:
        master_hash = crypto.modified_hash(master_password, keyfile_path=keyfile_path)
    except Exception as e:
        print(f"{ANSI_COLORS['red']}Error reading key file: {e}{ANSI_COLORS['reset']}")
        sys.exit(1)

    temporal_secret = get_temporal_secret(args)
    filename = os.path.expanduser(args.file)

    use_lower, use_upper = not args.no_lowercase, not args.no_uppercase
    use_digits, use_special = not args.no_numbers, not args.no_specials
    feat_bin = f"{int(use_lower)}{int(use_upper)}{int(use_digits)}{int(use_special)}"
    date_str = datetime.now().strftime("%Y%m%d%H%M%S")
    log_enabled, print_hash, encrypt_log = not args.write, not args.no_print_hash, not args.plain_log

    export_writer = export_handle = export_file = None
    if args.output:
        export_writer, export_handle, export_file = storage.get_export_writer(args.output)

    def process_line(app_password, identifiers):
        app_hash = crypto.modified_hash(app_password)
        try:
            pwd = crypto.generate_password('v2', master_hash, app_hash, args.length,
                                            temporal_salt=temporal_secret, use_upper=use_upper,
                                            use_lower=use_lower, use_digits=use_digits, use_special=use_special)
        except Exception as e:
            print(f"Error generating password for '{identifiers}': {e}")
            return
        print(f"Identifiers: {identifiers}")
        print(f"Generated password: {pwd}")
        if args.output:
            name, url, username = prompt_entry_info()
            export_writer.writerow(storage.EXPORT_FORMATS[args.output]["row"](name, url, username, pwd))
        storage.build_and_log_line(date_str, args.length, master_hash, app_hash, pwd, feat_bin,
                                    temporal_secret=temporal_secret, log_enabled=log_enabled,
                                    print_hash=print_hash, encrypt=encrypt_log, keyfile_path=keyfile_path)

    try:
        ext = os.path.splitext(filename)[1].lower()
        if ext == ".csv":
            with open(filename, newline='') as f:
                rows = list(csv.reader(f))
            if rows and any(h.lower() in ["password", "senha", "app", "passphrase"] for h in rows[0]):
                rows = rows[1:]
            for row in rows:
                if len(row) < 2:
                    print("Skipping CSV row with less than 2 fields.")
                    continue
                process_line(row[0], row[1])
        else:
            with open(filename, 'r') as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                process_line(parts[0], parts[1] if len(parts) > 1 else '')
    except FileNotFoundError:
        print(f"Batch file '{filename}' not found.")
    finally:
        if export_handle:
            export_handle.close()
            print(f"{ANSI_COLORS['green']}{_('export_success', 'File successfully exported to: ')}{export_file}{ANSI_COLORS['reset']}")

def run_mass_rekey(args):
    old_master = getpass.getpass(_('old_master_prompt', "Old master password: "))
    new_master = getpass.getpass(_('new_master_prompt_plain', "New master password: "))
    new_master_confirm = getpass.getpass(_('master_prompt_confirm', "Confirm Master password: "))
    if new_master != new_master_confirm:
        print(f"{ANSI_COLORS['red']}{_('master_mismatch', 'ERROR: Password mismatch. Aborting.')}{ANSI_COLORS['reset']}")
        sys.exit(1)

    old_keyfile = os.path.expanduser(args.old_key_file) if args.old_key_file else None
    new_keyfile = os.path.expanduser(args.new_key_file) if args.new_key_file else None
    try:
        old_master_hash = crypto.modified_hash(old_master, keyfile_path=old_keyfile)
        new_master_hash = crypto.modified_hash(new_master, keyfile_path=new_keyfile)
    except Exception as e:
        print(f"{ANSI_COLORS['red']}Error reading key file: {e}{ANSI_COLORS['reset']}")
        sys.exit(1)

    try:
        hosts_content = storage.read_encrypted_hosts(old_master_hash)
    except ValueError:
        hosts_content = None
    if not hosts_content:
        print(f"{ANSI_COLORS['red']}No hosts list found, or it could not be decrypted with the old master password.{ANSI_COLORS['reset']}")
        sys.exit(1)

    contexts = [line.strip() for line in hosts_content.splitlines() if line.strip()]
    if not contexts:
        print(f"{ANSI_COLORS['yellow']}Hosts list is empty, nothing to rekey.{ANSI_COLORS['reset']}")
        sys.exit(0)

    use_lower, use_upper = not args.no_lowercase, not args.no_uppercase
    use_digits, use_special = not args.no_numbers, not args.no_specials
    feat_bin = f"{int(use_lower)}{int(use_upper)}{int(use_digits)}{int(use_special)}"
    date_str = datetime.now().strftime("%Y%m%d%H%M%S")
    log_enabled, print_hash, encrypt_log = not args.write, not args.no_print_hash, not args.plain_log
    export_format = args.output or 'bitwarden'
    writer, export_handle, export_file = storage.get_export_writer(export_format)

    for context in contexts:
        app_hash = crypto.modified_hash(context)
        try:
            old_pwd = crypto.generate_password('v2', old_master_hash, app_hash, args.length,
                                                use_upper=use_upper, use_lower=use_lower,
                                                use_digits=use_digits, use_special=use_special)
            new_pwd = crypto.generate_password('v2', new_master_hash, app_hash, args.length,
                                                use_upper=use_upper, use_lower=use_lower,
                                                use_digits=use_digits, use_special=use_special)
        except Exception as e:
            print(f"Error rekeying context '{context}': {e}")
            continue
        print(f"{ANSI_COLORS['cyan']}{context}{ANSI_COLORS['reset']}: {ANSI_COLORS['yellow']}{old_pwd}{ANSI_COLORS['reset']} -> {ANSI_COLORS['green']}{new_pwd}{ANSI_COLORS['reset']}")
        writer.writerow(storage.EXPORT_FORMATS[export_format]["row"](context, "", "", old_pwd))
        writer.writerow(storage.EXPORT_FORMATS[export_format]["row"](context, "", "", new_pwd))
        storage.build_and_log_line(date_str, args.length, old_master_hash, app_hash, old_pwd, feat_bin,
                                    change_mode=True, log_enabled=log_enabled, print_hash=print_hash, encrypt=encrypt_log)
        storage.build_and_log_line(date_str, args.length, new_master_hash, app_hash, new_pwd, feat_bin,
                                    change_mode=True, log_enabled=log_enabled, print_hash=print_hash, encrypt=encrypt_log)

    export_handle.close()
    print(f"{ANSI_COLORS['green']}{_('export_success', 'File successfully exported to: ')}{export_file}{ANSI_COLORS['reset']}")

    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
        tmp.write(hosts_content)
        tmp_path = tmp.name
    try:
        storage.encrypt_and_save_hosts(new_master_hash, tmp_path)
    finally:
        os.unlink(tmp_path)
    print(f"{ANSI_COLORS['green']}hosts.enc re-encrypted under the new master password.{ANSI_COLORS['reset']}")

def run_fido2_register():
    try:
        credential_id = crypto.register_fido2_credential()
    except Exception as e:
        print(f"{ANSI_COLORS['red']}FIDO2 registration error: {e}{ANSI_COLORS['reset']}")
        sys.exit(1)
    cred_path = os.path.expanduser("~/.passweird/fido2.cred")
    os.makedirs(os.path.dirname(cred_path), exist_ok=True)
    with open(cred_path, "wb") as f:
        f.write(credential_id)
    print(f"{ANSI_COLORS['green']}FIDO2 credential registered and saved to: {cred_path}{ANSI_COLORS['reset']}")

def main():
    cfg = storage.load_settings()
    parser = build_parser(cfg)
    args = parser.parse_args()

    # Validated here rather than letting crypto raise, so a bad --rsa value fails
    # immediately with a readable message instead of after the master password prompt.
    if args.rsa is not None and (args.rsa < 2048 or args.rsa % 16 != 0):
        parser.error(_('arg_rsa_invalid',
                       "--rsa must be at least 2048 and a multiple of 16 (got %d)") % args.rsa)

    if args.gen_temporal is not None:
        try:
            secret, bits, source = storage.generate_temporal_secret(args.gen_temporal)
        except ValueError as e:
            parser.error(str(e))
        print(f"\n{ANSI_COLORS['cyan']}{_('gen_temporal_title', '=== Random Temporal Secret ===')}{ANSI_COLORS['reset']}\n")
        print(f"  {ANSI_COLORS['green']}{secret}{ANSI_COLORS['reset']}\n")
        # The bit count is printed because it is the whole point: it is a number you
        # can check, and it stays true even if an attacker knows exactly how this was
        # drawn - which is precisely what invented "clever" secrets cannot claim.
        print(_('gen_temporal_bits', "Entropy: {:.0f} bits (source: {})").format(bits, source))
        print(f"{ANSI_COLORS['yellow']}{_('gen_temporal_warn', 'Write it down somewhere safe before using it: it is not recoverable, and losing it loses every secret derived with it.')}{ANSI_COLORS['reset']}")
        sys.exit(0)

    if args.generate:
        config_path = os.path.expanduser("~/.passweird/passweird.cfg")
        storage.create_default_config(config_path)
        sys.exit(0)

    if args.save_settings:
        current_cfg = {
            'length': args.length,
            'paranoid': args.paranoid,
            'no_uppercase': args.no_uppercase,
            'no_lowercase': args.no_lowercase,
            'no_numbers': args.no_numbers,
            'no_specials': args.no_specials,
            'change': args.change,
            'write': args.write,
            'no_print_hash': args.no_print_hash,
            'invisible_password': args.invisible_password or '',
            'file': args.file or '',
            'temporal_secret_file': args.temporal_secret_file or '',
        }
        saved_file = storage.save_settings(current_cfg)
        print(f"\n{ANSI_COLORS['green']}{_('cfg_saved', 'Preferences successfully saved to: ')}{saved_file}{ANSI_COLORS['reset']}\n")
        sys.exit(0)

    print(f"\n{ANSI_COLORS['blue']}=== Passweird Identity Engine (GPLv3) ==={ANSI_COLORS['reset']}\n")

    if args.change:
        run_change_mode(args)
        return

    if args.file:
        run_batch_mode(args)
        return

    if args.mass_rekey:
        run_mass_rekey(args)
        return

    if args.fido2_register:
        run_fido2_register()
        return

    # Double confirmation prompt for master password setup
    is_registered = storage.check_master_hash("") is not None
    if args.register_master and not is_registered:
        master = getpass.getpass(_('master_prompt', "Master password: "))
        master_confirm = getpass.getpass(_('master_prompt_confirm', "Confirm Master password: "))
        if master != master_confirm:
            print(f"{ANSI_COLORS['red']}{_('master_mismatch', 'ERROR: Password mismatch. Aborting.')}{ANSI_COLORS['reset']}")
            sys.exit(1)
    else:
        master = get_master_password(args)

    keyfile_path = os.path.expanduser(args.key_file) if args.key_file else None
    try:
        master_hash = crypto.modified_hash(master, keyfile_path=keyfile_path)
    except Exception as e:
        print(f"{ANSI_COLORS['red']}Error reading key file: {e}{ANSI_COLORS['reset']}")
        sys.exit(1)

    if not args.no_check and not args.register_master:
        is_valid = storage.check_master_hash(master_hash)
        if is_valid is False:
            print(f"{ANSI_COLORS['red']}{_('err_master_match', 'CRITICAL ERROR: Input master password DOES NOT match the registered one!')}{ANSI_COLORS['reset']}")
            sys.exit(1)

    if args.register_master:
        storage.save_master_hash(master_hash)
        print(f"{ANSI_COLORS['green']}{_('master_registered', 'Master password hash successfully registered for future validations!')}{ANSI_COLORS['reset']}")
        sys.exit(0)

    # --- EXTERNAL KEYFILE GENERATION ---
    if args.gen_keyfile:
        output_path = os.path.expanduser(args.gen_keyfile)
        try:
            if args.recoverable:
                phrase = getpass.getpass(_('recovery_phrase_prompt', "Recovery phrase (needed to regenerate this keyfile later): "))
                phrase_confirm = getpass.getpass(_('recovery_phrase_confirm', "Confirm recovery phrase: "))
                if phrase != phrase_confirm:
                    print(f"{ANSI_COLORS['red']}{_('master_mismatch', 'ERROR: Password mismatch. Aborting.')}{ANSI_COLORS['reset']}")
                    sys.exit(1)
                crypto.generate_hybrid_keyfile(master_hash, phrase, output_path)
                print(f"{ANSI_COLORS['green']}Recoverable keyfile written to: {output_path}{ANSI_COLORS['reset']}")
                print(f"{ANSI_COLORS['yellow']}Keep the recovery phrase memorized -- it, plus your master password, can regenerate this file.{ANSI_COLORS['reset']}")
            else:
                crypto.generate_random_keyfile(master_hash, output_path)
                print(f"{ANSI_COLORS['green']}Random keyfile written to: {output_path}{ANSI_COLORS['reset']}")
                print(f"{ANSI_COLORS['yellow']}This is a pure possession factor: back it up, losing it means losing the factor.{ANSI_COLORS['reset']}")
            print(f"Use it later with: --key-file {output_path}")
            sys.exit(0)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}Error generating keyfile: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)

    # --- ENCRYPTED HOSTS LIST PIPELINES ---
    if args.encrypt_list:
        try:
            out_path = storage.encrypt_and_save_hosts(master_hash, os.path.expanduser(args.encrypt_list))
            print(f"{ANSI_COLORS['green']}Hosts/Systems list successfully encrypted and saved to: {out_path}{ANSI_COLORS['reset']}")
            sys.exit(0)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}Error encrypting hosts list: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)

    if args.view_list:
        try:
            content = storage.read_encrypted_hosts(master_hash)
            if content:
                print(f"\n{ANSI_COLORS['cyan']}=== Decrypted Hosts/Systems List ==={ANSI_COLORS['reset']}\n")
                print(content)
            else:
                print(f"{ANSI_COLORS['yellow']}No encrypted hosts list found or decryption failed.{ANSI_COLORS['reset']}")
            sys.exit(0)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}Error reading hosts list: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)

    # --- VIEW DECRYPTED LOGS ---
    if args.view_log:
        print(f"\n{ANSI_COLORS['cyan']}=== Decrypted Local History Log ==={ANSI_COLORS['reset']}\n")
        records = storage.read_logs_from_file(master_hash)
        if records:
            for r in records:
                print(f"  --> {r}")
        else:
            print(f"{ANSI_COLORS['yellow']}No records found or decryption failed (invalid master key).{ANSI_COLORS['reset']}")
        sys.exit(0)

    # --- AUDIT PIPELINE ---
    if args.audit:
        if args.app_name or args.temporal:
            app = args.app_name if args.app_name else ""
            temporal = args.temporal or ""
            print(_('audit_cli', "Audit Mode (Command Line interface)..."))
        else:
            print(f"{ANSI_COLORS['magenta']}{_('audit_inter', 'Audit Mode Active (Interactive & Hidden)...')}{ANSI_COLORS['reset']}")
            app = getpass.getpass(_('audit_app_prompt', "Enter Application/Context Name (Hidden): ")).strip()
            temporal = getpass.getpass(_('audit_time_prompt', "Enter Temporal Key if applicable (Hidden): ")).strip()

        app_hash = crypto.modified_hash(app)
        app_sum = crypto.summarize_hash(app_hash)

        records = storage.find_in_log(app_sum, temporal, master_hash)
        if records:
            print(f"\n{ANSI_COLORS['green']}{_('audit_match', '✔ MATCH FOUND IN LOG HISTORY:')}{ANSI_COLORS['reset']}")
            for r in records:
                print(f"  --> {r}")
        else:
            print(f"\n{ANSI_COLORS['yellow']}{_('audit_no_match', '❌ NO RECORD FOUND in local log history for the provided credentials.')}{ANSI_COLORS['reset']}")
        sys.exit(0)

    # --- APPLICATION CONTEXT CAPTURE ---
    if args.app_name:
        app = args.app_name
    elif args.paranoid:
        app = getpass.getpass(_('app_hidden', "Application/Context Name (HIDDEN MODE): "))
    else:
        app = input(_('app_prompt', "Application/Context Name (e.g., ufpb-sigaa): ")).strip()

    if not app:
        print(f"{ANSI_COLORS['red']}{_('err_empty_app', 'Error: Application context cannot be empty.')}{ANSI_COLORS['reset']}")
        sys.exit(1)

    app_hash = crypto.modified_hash(app)
    app_sum = crypto.summarize_hash(app_hash)

    # --- FIDO2 SECONDARY FACTOR (per-app-context, requires a physical touch) ---
    if args.fido2:
        cred_path = os.path.expanduser("~/.passweird/fido2.cred")
        if not os.path.exists(cred_path):
            print(f"{ANSI_COLORS['red']}No FIDO2 credential registered yet. Run --fido2-register first.{ANSI_COLORS['reset']}")
            sys.exit(1)
        with open(cred_path, "rb") as f:
            credential_id = f.read()
        salt = hashlib.sha256(app_hash.encode()).digest()
        try:
            fido2_secret = crypto.derive_fido2_secret(credential_id, salt)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}FIDO2 error: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)
        master_hash = crypto.blend_secondary_factor(master_hash, fido2_secret)

    temporal_secret = get_temporal_secret(args)

    # --- SSH KEY GENERATION PIPELINE ---
    if args.ssh:
        try:
            # The SSH public key does not carry the context, so an unpredictable
            # context name does add entropy here — hence publishes_context=False.
            warn_temporal_strength(temporal_secret)
            priv, pub = crypto.generate_deterministic_ssh_key(master_hash, app_hash, temporal_secret)
            print(f"\n{ANSI_COLORS['cyan']}=== SSH Ed25519 Deterministic Key Pair ==={ANSI_COLORS['reset']}")
            print(f"\n{ANSI_COLORS['green']}[PUBLIC KEY]{ANSI_COLORS['reset']}")
            print(pub)
            print(f"\n{ANSI_COLORS['yellow']}[PRIVATE KEY (OpenSSH)]{ANSI_COLORS['reset']}")
            print(priv)
            sys.exit(0)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}SSH Gen Error: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)

    # --- SSL CERTIFICATE GENERATION PIPELINE ---
    if args.ssl or args.rsa:
        try:
            use_rsa = args.rsa is not None
            bits = args.rsa if use_rsa else 2048
            # publishes_context=True: the CN carries the context name in clear, so it
            # contributes no guessing entropy against whoever holds the certificate.
            warn_temporal_strength(temporal_secret, publishes_context=True)
            if use_rsa and bits >= 4096:
                print(f"{ANSI_COLORS['yellow']}{_('rsa_slow', 'Deriving RSA primes, this may take a few seconds...')}{ANSI_COLORS['reset']}")
            priv, cert = crypto.generate_ssl_certificate(master_hash, app_hash, app, use_rsa=use_rsa,
                                                         rsa_bits=bits, temporal_salt=temporal_secret)
            print(f"\n{ANSI_COLORS['cyan']}=== Deterministic SSL/TLS Self-Signed Certificate ==={ANSI_COLORS['reset']}")
            print(f"\n{ANSI_COLORS['green']}[CERTIFICATE (PEM)]{ANSI_COLORS['reset']}")
            print(cert)
            print(f"\n{ANSI_COLORS['yellow']}[PRIVATE KEY (PEM)]{ANSI_COLORS['reset']}")
            print(priv)
            sys.exit(0)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}SSL Gen Error: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)

    # --- TOTP SECRET GENERATION PIPELINE ---
    if args.totp:
        try:
            import pyotp
            secret = crypto.generate_deterministic_totp_secret(master_hash, app_hash, temporal_secret)
            totp = pyotp.TOTP(secret)
            print(f"\n{ANSI_COLORS['cyan']}=== Deterministic TOTP Secret ==={ANSI_COLORS['reset']}")
            print(f"{ANSI_COLORS['green']}[BASE32 SECRET]{ANSI_COLORS['reset']} {secret}")
            print(f"{ANSI_COLORS['green']}[otpauth URI]{ANSI_COLORS['reset']} {totp.provisioning_uri(name=app, issuer_name='Passweird')}")
            print(f"{ANSI_COLORS['yellow']}[CURRENT CODE]{ANSI_COLORS['reset']} {totp.now()}")
            sys.exit(0)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}TOTP Gen Error: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)

    # --- PGP KEY GENERATION PIPELINE ---
    if args.pgp:
        try:
            # The UID below embeds the context verbatim, so like the certificate CN it
            # publishes the context name — same reasoning as the SSL pipeline.
            warn_temporal_strength(temporal_secret, publishes_context=True)
            raw_packets = crypto.generate_deterministic_pgp_key(master_hash, app_hash, temporal_secret, uid=f"Passweird <{app}>")
            pub, priv, fpr = crypto.export_pgp_key_armored(raw_packets)
            print(f"\n{ANSI_COLORS['cyan']}=== Deterministic PGP/OpenPGP Key Pair ==={ANSI_COLORS['reset']}")
            print(f"{ANSI_COLORS['green']}[FINGERPRINT]{ANSI_COLORS['reset']} {fpr}")
            print(f"\n{ANSI_COLORS['green']}[PUBLIC KEY]{ANSI_COLORS['reset']}")
            print(pub)
            print(f"\n{ANSI_COLORS['yellow']}[PRIVATE KEY]{ANSI_COLORS['reset']}")
            print(priv)
            sys.exit(0)
        except Exception as e:
            print(f"{ANSI_COLORS['red']}PGP Gen Error: {e}{ANSI_COLORS['reset']}")
            sys.exit(1)

    # --- STANDARD PASSWORD GENERATION PIPELINE ---
    use_lower = not args.no_lowercase
    use_upper = not args.no_uppercase
    use_digits = not args.no_numbers
    use_special = not args.no_specials
    feat_bin = f"{int(use_lower)}{int(use_upper)}{int(use_digits)}{int(use_special)}"

    if not args.force:
        prior = storage.find_last_features(app_sum, master_hash)
        if prior is not None and (prior[0] != args.length or prior[1] != feat_bin):
            print(f"{ANSI_COLORS['yellow']}WARNING: last time you used length={prior[0]} feat={prior[1]} for this context; "
                  f"now using length={args.length} feat={feat_bin}.{ANSI_COLORS['reset']}")
            confirm = input(_('confirm_mismatch', "Continue anyway? [y/N]: ")).strip().lower()
            if confirm != 'y':
                sys.exit(0)

    try:
        pwd = crypto.generate_password(
            args.version, master_hash, app_hash, args.length, temporal_salt=temporal_secret,
            use_upper=use_upper, use_lower=use_lower, use_digits=use_digits, use_special=use_special
        )

        app_display = "******** (Hidden)" if args.paranoid else app
        print(f"{_('context', 'Context: ')}{ANSI_COLORS['cyan']}{app_display}{ANSI_COLORS['reset']}")
        if temporal_secret:
            print(f"{_('time_flag', 'Temporal (-T): ')}{ANSI_COLORS['cyan']}{temporal_secret}{ANSI_COLORS['reset']}")

        color_name = args.invisible_password.lower() if args.invisible_password else None
        invisible_color = ANSI_COLORS.get(color_name) if color_name else None
        pwd_color = invisible_color or ANSI_COLORS['green']
        print(f"{_('gen_pwd', 'Generated Password: ')}{pwd_color}{pwd}{ANSI_COLORS['reset']}\n")

        if not (use_upper and use_lower and use_digits and use_special):
            print(f"{ANSI_COLORS['yellow']}{_('warn_disabled_chars', 'WARNING: Custom configuration disabled one or more character classes.')}")
            print(f"{_('warn_disabled_remind', 'Remember to keep track of the flags used to avoid future generation issues.')}{ANSI_COLORS['reset']}\n")

        if args.output:
            name, url, username = prompt_entry_info()
            saved_file = storage.export_to_csv(args.output, name, url, username, pwd)
            print(f"{ANSI_COLORS['green']}{_('export_success', 'File successfully exported to: ')}{saved_file}{ANSI_COLORS['reset']}")

        date_str = datetime.now().strftime("%Y%m%d%H%M%S")
        log_enabled, print_hash, encrypt_log = not args.write, not args.no_print_hash, not args.plain_log
        storage.build_and_log_line(date_str, args.length, master_hash, app_hash, pwd, feat_bin,
                                    temporal_secret=temporal_secret, log_enabled=log_enabled,
                                    print_hash=print_hash, encrypt=encrypt_log, keyfile_path=keyfile_path)

    except Exception as e:
        print(f"{ANSI_COLORS['red']}Execution Error: {e}{ANSI_COLORS['reset']}")

if __name__ == "__main__":
    main()
