# Action plan

Three fronts, independent of each other. Front 2 has already been implemented; fronts 1 and 3
remain.

---

## 1. Batch processing of keyring files

**Goal.** Read an existing keyring export (KeePassXC, Bitwarden, …), walk entry by entry,
suggest a context name from the URL, generate the new password under the current pattern, and
write a new file — with individual confirmation per entry.

Architecture decisions in [ADR-0005](adr/0005-processamento-em-lote-de-chaveiros.md).

### 1.1 Reading keyrings (`storage.py`)

`EXPORT_FORMATS` (storage.py:12) today only knows how to **write**: it has `header` and a `row`
lambda. The inverse map is missing. Extend each entry with a `fields` dict linking canonical
names to that format's columns:

```python
"keepassxc": {
    "filename_prefix": "keepassxc",
    "header": ["Title", "Username", "Password", "URL", "Notes"],
    "row": lambda name, url, username, pwd: [name, username, pwd, url, ""],
    "fields": {"name": "Title", "username": "Username", "password": "Password", "url": "URL"},
},
```

All seven formats need `fields`. Note that `firefox` has no title column — the canonical name
should fall back to the URL in that case.

New functions:

- `detect_vault_format(header_row)` — compares the read header against each format's `header`.
  The seven headers are textually distinct (`Title` vs `Name` vs `title` vs `name`), so the
  match is unambiguous. Returns `None` if nothing matches.
- `read_vault_csv(path, vault_format=None)` — uses `csv.DictReader`; if `vault_format` is
  `None`, calls `detect_vault_format`. Returns a list of canonical dicts
  `{"name", "url", "username", "password"}`. Reuses the already-imported `csv`.
- `suggest_context_from_url(url, fallback_name)` — strips scheme, `www.` and path, keeping the
  host; falls back to `fallback_name` when the URL is empty or invalid. This is the suggestion
  the user accepts with Enter or overrides.

`write_export_csv` already exists (storage.py:805) and is reused for writing.

### 1.2 Interactive pipeline (`main.py`)

New flags:

| Flag | Function |
|---|---|
| `--vault-in PATH` | Keyring file to process |
| `--vault-out PATH` | File to generate (mandatory; never overwrites the input) |
| `--vault-format NAME` | Forces the input format, turning off autodetection |
| `-o/--output` | Already exists; sets the **output** format (may differ from the input) |

Flow:

1. **Secrets first, once.** Master password via `get_master_password` and temporal secret via
   `getpass` (not `input`, unlike the regular flow — in batch mode the secret would stay on
   screen much longer). If provided via `--master-pass`/`-T`, trigger the existing
   `storage.print_command_line_warning()`.
2. For each entry: show Title / URL / Username and the suggested context.
3. Read the decision: Enter accepts the suggestion, new text replaces it, `s` skips the entry
   keeping the old password, `q` stops and writes what has been done so far.
4. Generate the password with `crypto.generate_password('v2', ...)` and the current flags; show
   it; confirm.
5. On confirmation, log it via `storage.build_and_log_line` (storage.py:763) — this way the
   entry becomes visible to front 3.
6. At the end, `write_export_csv` for the output format.

### 1.3 Security of the generated file

Every keyring format is CSV with passwords in plain text. On completion, print an explicit
warning: import it into the keyring and **delete the file**. Create it with `os.open(..., 0o600)`
instead of a plain `open()`.

### 1.4 Tests

- Round-trip per format: write with `write_export_csv`, read with `read_vault_csv`, compare.
- `detect_vault_format` gets all 7 right and returns `None` for an unknown header.
- `suggest_context_from_url` for `https://www.site.com/login?x=1` → `site.com`; empty URL →
  fallback; invalid URL → fallback.
- End-to-end pipeline with mocked input, covering accept / edit / skip / interrupt.
- Master password and temporal secret are asked **only once**, even with N entries.
- Output file is created with mode `0600`.
- The input file is never modified.

---

## 2. `--view-log` with mixed-format logs — ✅ DONE

**State verified (before the fix).** Worked on a 100% encrypted log and a 100% plaintext log.
**Broke on a mixed log**, which arises naturally from using `--plain-log` once and then going
back to the default:

| Order | Symptom |
|---|---|
| plaintext → encrypted | `UnicodeDecodeError`, traceback, **entire log lost** |
| encrypted → plaintext | **silent loss**: 2 records written, 1 shown |

The second is the worse one: no error, just absence.

**Cause.** `storage.read_logs_from_file` (storage.py:725) picked the format by looking **only at
the first 14 bytes of the file**, then treated the whole file as that type.

**Fix.** Decide the format **per record**, not per file. Walk the buffer:

- if the next 14 bytes are ASCII digits → plaintext line, read up to `\n`;
- otherwise → encrypted block, read the 4-byte prefix + payload.

The discriminator remains valid record by record: an encrypted block's length prefix starts
with `\x00\x00\x00` for any realistic payload, and is never an ASCII digit. This is exactly the
argument already recorded in the function's docstring — it just was not being applied per
record.

Decisions in [ADR-0006](adr/0006-formato-do-log-e-deteccao-por-registro.md).

**Tests.** Encrypted-only log; plaintext-only log; mixed in both orders; empty log; log truncated
mid-block (must not raise); wrong master password returns an empty list without blowing up.

---

## 3. Password verification against the log

**What exists.** `--audit` (main.py:459) answers "does a record exist for this context?", via
`storage.find_in_log`. It does **not** verify the password and returns every occurrence, with no
notion of which is the most recent.

**What is missing** is what was requested: ask for the factors, regenerate the password, and
compare against the **most recently documented change** for that system, scanning the log
bottom-up.

Decisions and limits in [ADR-0007](adr/0007-verificacao-de-senha-contra-o-log.md).

### 3.1 `storage.py`

`find_last_entry(app_summary, temporal_salt, master_hash=None)` — scans
`read_logs_from_file` **back to front** and returns the first match as a dict of already-parsed
fields (`date`, `len`, `feat`, `pwd`, `changed`), or `None`. Shares the token parser with
`find_last_features` (storage.py:860), which currently duplicates this logic — extract
`_parse_log_tokens(line)` and use it in both.

### 3.2 `main.py`

`--verify` flag. Flow:

1. Ask for the context and temporal secret via `getpass` (hidden), the same pattern as
   `--audit`'s interactive mode — leaves no trace in shell history.
2. `find_last_entry` to find the most recent record for that context.
3. Regenerate the password using `len`/`feat` **from the record itself**, not the command-line
   flags. Without this the comparison would fail every time the default pattern had changed.
4. Compare `crypto.summarize_password_hash(password)` against the record's `pwd:` field.

Three outcomes, distinct and explicit:

| Outcome | Meaning |
|---|---|
| No record | Never generated, or generated with `-w` (logging off). **Not** "wrong password" |
| Record, matches | The current password reproduces the last documented change |
| Record, diverges | Some factor changed since then (master password, temporal, or context) |

Show the record's date and whether it carries the ` C` marker (change mode).

### 3.3 Tests

- Matches right after generation; diverges with a wrong master password; diverges with a wrong
  temporal secret.
- With several entries for the same context, returns the **latest** one (chronological log
  order).
- Absence of a record is reported as absence, not as a mismatch.
- Regeneration uses the record's `len`/`feat`, not the defaults — tested with diverging flags.
- Works with an encrypted log and with a plaintext log (depends on front 2).

---

## Overall verification

```bash
cd /home/janio/Documentos/Pessoais/Code/Passweird
python -m pytest tests/ -v
python -m pytest tests/ -v -m "not slow"

# front 2, the case that broke before the fix
python main.py site-a -T ""
python main.py site-b -T "" --plain-log
python main.py --view-log          # must list both entries

# front 1, end to end
python main.py --vault-in ~/keepass-export.csv --vault-out /tmp/new.csv -o keepassxc
ls -l /tmp/new.csv                 # must be created 0600

# front 3
python main.py --verify
```
