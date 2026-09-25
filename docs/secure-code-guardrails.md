# Secure-code guardrails

AI coding agents write a lot of code quickly, and some of it takes shortcuts a
reviewer would reject: TLS verification switched off, SQL built from request
data, `shell=True` with interpolated input, world-writable files. Singularity
AIDR checks the code an agent writes as it writes it and tells both the
developer and the agent what to fix.

The guardrails are **advisory by default**: the write goes through, the
developer sees a notice, the agent is told what to correct, and the finding is
counted in the local audit log. Teams that want a hard stop can switch them to
`ask`.

## What is checked

| Rule | Languages | Detects | Secure alternative |
|------|-----------|---------|--------------------|
| SCG-TLS-001 | Python | `verify=False`, `ssl._create_unverified_context`, `check_hostname = False`, `CERT_NONE` | keep verification, point to a private CA bundle |
| SCG-TLS-002 | JavaScript, TypeScript | `rejectUnauthorized: false`, `strictSSL: false`, no-op `checkServerIdentity` | pass the private CA via `ca` |
| SCG-TLS-003 | JS/TS, Python, shell, Dockerfile, Makefile, YAML, `.env`, PowerShell | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0`, `GIT_SSL_NO_VERIFY=1` | trust the private CA instead |
| SCG-TLS-004 | Go | `InsecureSkipVerify: true` | configure `RootCAs` |
| SCG-TLS-005 | shell, Dockerfile, Makefile, YAML, PowerShell | `curl -k`/`--insecure`, `wget --no-check-certificate`, `http.sslVerify=false` | `--cacert` |
| SCG-TLS-006 | Java, Kotlin | trust-all hostname verifiers and trust managers | load the private CA into a TrustManager |
| SCG-EVAL-001 | Python | `eval`/`exec` on request data, `input()`, `sys.argv` | `json`, `ast.literal_eval` |
| SCG-EVAL-002 | JavaScript, TypeScript | `eval`, `new Function`, `vm.run*` on request data, `process.argv`, `location` | `JSON.parse` |
| SCG-SQLI-001 | Python | f-strings, `%` or `+` into `execute()`/`read_sql()`/`text()`; SQL strings built from `request.` | query parameters |
| SCG-SQLI-002 | JavaScript, TypeScript | template literals or concatenation into `query()`/`raw()`/`$queryRawUnsafe()` | `$1` / `?` parameters |
| SCG-SQLI-003 | Go | `fmt.Sprintf` or concatenation into `Query`/`Exec`/`Raw`/`Where` | query arguments |
| SCG-SQLI-004 | Java, Kotlin | concatenation into `executeQuery`/`prepareStatement`/`createQuery` | `?` placeholders |
| SCG-SQLI-005 | PHP | SQL built from `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` | prepared statements |
| SCG-CMDI-001 | Python | `subprocess(..., shell=True)` with an f-string/`%`/`+` command; `os.system`/`os.popen` with interpolation | argument list without `shell=True` |
| SCG-CMDI-002 | JavaScript, TypeScript | `exec`/`execSync` with a template literal or concatenation | `execFile`/`spawn` with an argument array |
| SCG-PERM-001 | shell, Dockerfile, Makefile, YAML, PowerShell | `chmod 777`, `chmod a+rwx` | the narrowest mode (755, 644) |
| SCG-PERM-002 | Python, JS/TS, Go, Ruby, PHP | `chmod`/`mkdir`/`WriteFile` with mode `0777`, `umask(0)` | the narrowest mode |
| SCG-CORS-001 | Python | any-origin CORS with credentials (FastAPI/Starlette, flask-cors, django-cors-headers) | list allowed origins |
| SCG-CORS-002 | JavaScript, TypeScript | `cors({ origin: "*" or true, credentials: true })` | list allowed origins |
| SCG-CORS-003 | JS/TS, Python, Go, Java, Kotlin, PHP, Ruby, C# | `Access-Control-Allow-Origin: *` (or reflected origin) with `Allow-Credentials: true` | list allowed origins |
| SCG-DEBUG-001 | Python | `app.run(host="0.0.0.0", debug=True)`, `run_simple(... use_debugger=True)` on all interfaces | bind to 127.0.0.1 or turn debug off |
| SCG-DEBUG-002 | shell, Dockerfile, Makefile, YAML, JSON, JS/TS | `flask run --debug --host 0.0.0.0`, `node --inspect=0.0.0.0` | bind the debugger to 127.0.0.1 |
| SCG-CSRF-001 | Python, Java, Kotlin, Ruby | `@csrf_exempt`, `WTF_CSRF_ENABLED = False`, `csrf().disable()`, `skip_before_action :verify_authenticity_token` | keep CSRF protection on |
| SCG-CRYPTO-001 | Python, JS/TS, Go, Java, Kotlin, PHP, Ruby | MD5/SHA-1 over passwords | Argon2, bcrypt, scrypt, PBKDF2 |
| SCG-CRYPTO-002 | Python, Java, Kotlin, JS/TS, C#, PHP, Ruby | ECB mode, including `Cipher.getInstance("AES")` | AES-GCM |
| SCG-CRYPTO-003 | JavaScript, TypeScript | `Math.random()` for tokens, passwords, nonces, salts | `crypto.randomBytes`, `crypto.randomUUID` |
| SCG-CRYPTO-004 | Python | the `random` module for tokens, passwords, nonces, salts | the `secrets` module |
| SCG-SECRET-001 | source files, shell, Dockerfile, Makefile, YAML | hard-coded credentials (tokens, API keys, private keys, password assignments) | environment variables or a secret manager |

SCG-SECRET-001 uses the same credential detectors as prompt protection, so a
credential is recognised the same way everywhere. Credentials in `.env` files
are not flagged: that is where they belong. The matched value is never copied
into a notice, the audit log or a scan report.

Every rule has a secure twin that stays silent, for example `verify=True`,
parameterised SQL, `subprocess.run(["ls", path])`, `chmod 755`,
`app.run(host="127.0.0.1", debug=True)` and `secrets.token_urlsafe()`.

## What is inspected

Only the code an agent **adds**, in a file whose language the rule is written
for:

- **Write**: the whole new file.
- **Edit / MultiEdit**: the lines of `new_string` that are not in `old_string`,
  so editing next to existing insecure code does not re-flag it.
- **apply_patch** (unified diff and Codex patch formats): the `+` lines, with the
  new-file line number when the patch carries one. Removed lines are never a
  finding.
- **NotebookEdit** and notebook writes: code cells only (Markdown cells are
  ignored).
- **Heredocs** written into source files from a shell command
  (`cat > app.py <<EOF`).

Languages are recognised by file extension (`.py`, `.js`/`.mjs`/`.cjs`/`.jsx`,
`.ts`/`.tsx`, `.go`, `.java`, `.kt`, `.rb`, `.php`, `.cs`, `.rs`, `.sh`/`.bash`/`.zsh`,
`.ps1`, `.yml`/`.yaml`, `.json`, `.ipynb`) and by name (`Dockerfile*`,
`Containerfile`, `Makefile`, `.env*`). Documentation such as Markdown is never
treated as code, so a README that explains why `verify=False` is dangerous is
not flagged.

## Configuration

```json
{
  "secure_code": {
    "enabled": true,
    "action": "warn"
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Turn the guardrails on or off. The AI model supply-chain rules are not affected. |
| `action` | `"warn"` | `"warn"`: the write goes through with a notice. `"ask"`: the write is held for review (the host's confirmation dialog or the operator approval channel). |

Individual rules are disabled with `disabled_threats`, for example
`["SCG-CRYPTO-003"]`. The guardrails need the local rule set, so
`heuristics_enabled: false` turns them off as well. A finding never becomes a
`deny` on its own, and a call that another rule already blocks keeps its
decision; the notice is added to the block message.

## How each connector shows a warning

| Connector | `warn` notice |
|-----------|---------------|
| Claude Code | `systemMessage` to the user and `additionalContext` to the model; the call continues through the normal permission flow |
| Cursor | `user_message` to the user and `agent_message` to the agent on the allowed call |
| VS Code | `systemMessage` to the user (the hook has no documented model-context field) |
| OpenClaw, OpenCode, Codex | recorded in the local audit log only: these hosts have no notice channel on an allowed tool call |

In every connector, `action: "ask"` uses the connector's normal review path
(Cursor and Codex, which have no working `ask`, block the call instead).

## Audit log

An allowed call with findings is written to the local audit log
(`~/.singularity-aidr/audit.jsonl`) with `category: "secure_code_warning"` and a
`secure_code` summary holding only counts and rule ids:

```json
{ "verdict": "allow", "category": "secure_code_warning",
  "secure_code": { "findings": 2, "rule_ids": ["SCG-SQLI-001", "SCG-TLS-001"] } }
```

The matched source text is never recorded, and the summary is not part of the
telemetry sent to a managed control plane.

## Scanning an existing project

`aidr scan --code <path>` applies the same rules, together with the
[AI model supply-chain rules](ai-supply-chain-safety.md), to every supported
file in a project and prints each finding as `file:line` with the offending
line (credentials masked). See that page for exit codes and scope.

## Limitations

The guardrails are pattern rules over the text being written. They catch
direct, idiomatic mistakes; they do not trace data flow (an `execute(query)`
whose `query` was concatenated three lines earlier in another edit is not
linked), and they are not a replacement for a full static analysis or code
review. Findings are warnings to help the developer and the agent, not a
certification that the remaining code is secure.
