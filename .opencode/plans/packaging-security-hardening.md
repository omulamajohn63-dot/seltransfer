# SELTRANSFER — Packaging & Security Hardening Plan

## Phase 0 — Repository audit (derived, not guessed)

```text
Existing tests:              120 Python (92 def test_* + 28 parametrised) + 12 Node.
                             9 Python files + tests/web/test_app.js. All passing.
                             No tests/conftest.py exists. No WebRTC endpoint test at all.

Existing packaging support:   setuptools build backend, src/ layout, console_script
                             `seltransfer = seltransfer.cli:app`, package-data for
                             web/templates/*.html and web/static/*. pyproject 62.
                             tests/test_packaging.py builds a real wheel (4 tests).
                             NO PyInstaller spec, NO dist/, NO build/.

Current executable entry:    console script only. `python -m seltransfer` FAILS
                             (no __main__.py). Typer app is directly callable.

Current application-data:     resolve_app_dir() -> %SELTRANSFER_APP_DIR% else
                             Path.home()/".seltransfer". Ignores the `platform`
                             argument by design (test_transfers.py:18).
                             config.py:76-77 mkdir()s on IMPORT. Carries
                             history.db, downloads/, device-id.

Current security controls:   CORS restricted to private origins, credentials off.
                             /docs,/redoc,/openapi.json removed unless expose_docs.
                             Device.public() strips session_id (devices.py:130).
                             Pydantic patterns on device_id (^[A-Za-z0-9._-]{8,128}$).
                             safe_relative_path rejects absolute, drive, UNC,
                             "..", empty parts, and control chars.
                             Per-file + per-transfer limits, enforced pre- and
                             mid-stream. .part -> verify -> rename, with rollback.
                             SHA-256 verified before VERIFIED. compare_digest for
                             tokens. Role-explicit state changes. Caller-scoped
                             history. Parameterised SQL only. No innerHTML anywhere.

Current known weaknesses:    (all derived below, with file:line)
                             W1  Unauthenticated pairing                routes.py:386
                             W2  Unauthenticated == local node identity routes.py:129
                             W3  Unbounded transfers/sessions/webrtc    app.py:65-73
                             W4  Unbounded sender metadata dict         routes.py:61
                             W5  transfer_id has no pattern (log inject) routes.py:60
                             W6  Windows reserved filenames accepted    transfers.py:36
                             W7  received_files positional -> wrong file transfers.py:207
                             W8  Duplicate upload double-counts        transfers.py:207
                             W9  No TrustedHost (DNS rebinding)        app.py:47
                             W10 No security headers / CSP             app.py:47
                             W11 /api/connection leaks absolute path    routes.py:204
                             W12 Firewalld rule program=System          cli.py:192
                             W13 Firewall idempotency ignores port      cli.py:184
                             W14 status/discover hardcode port 8765    cli.py:220,233
                             W15 4 independent version literals         __init__/devices/app/pyproject
                             W16 __file__ asset path breaks when frozen app.py:114
                             W17 Tests write to the real ~/.seltransfer  (no conftest)
                             W18 CLI prints Session row that is always "n/a" app.js:74

Current HTTP architecture:   FastAPI + uvicorn on 0.0.0.0:8765. Plain HTTP.
                             Browser is a CLIENT of the same server (cannot listen),
                             so PC uploads to its own server and the phone pulls
                             back via an authorised GET. Upload auth = per-transfer
                             token in x-seltransfer-token. Session auth =
                             x-seltransfer-session header -> browser_sessions dict.

Current WebRTC architecture: Server-side signalling relay only, stored in an
                             in-memory dict. RTCPeerConnection() is constructed with
                             NO configuration, so iceServers is [] and no STUN/TURN
                             lookup is ever attempted. This is why it works offline.
```

### Existing tests (the "before" number)

```text
120 Python passed, 12 Node passed, ruff clean, mypy clean on 12 files.
```

## Verified security findings

I read every route and traced the control flow. Two I confirmed against the real
code path; the rest are structural and cited to line.

**W1 — Unauthenticated pairing (high).** `routes.py:386-393`:

```python
@router.post("/api/devices/{device_id}/pair")
async def pair_device(device_id: str, request: Request):
    device = registry.get(device_id)
    if not device: raise HTTPException(404, ...)
    request.app.state.paired_devices.add(device_id)   # no auth, no confirmation
```

No session check, no caller check, no confirmation. Device IDs are readable by
anyone from the unauthenticated `GET /api/devices`. So any LAN client can pair any
device, then create transfers to it. `paired_devices` also never expires. No test
covers this endpoint at all — every test reaches into `app.state.paired_devices`
directly.

**W2 — Unauthenticated callers are treated as the local node (high).**
`routes.py:129-136` falls back to `local_device.device_id` when no session header
is present. An unauthenticated LAN client therefore inherits the local node's
identity, which lets it read local history, cancel/pause/resume local transfers,
clear local history, and (for an accepted transfer) obtain the upload token.
`test_authorization.py:133` currently asserts an unauthenticated `GET /api/transfers`
returns `[]` — that passes only because no local-node transfers exist in the fixture.

**W7 — Out-of-order upload serves the wrong file (integrity, medium).**
`transfers.py:207` appends to `received_files` in completion order, but
`routes.py:621-624` reads it positionally by declared index. Uploading index 1
before index 0 makes `GET .../files/0` return the bytes for index 1. The CLI
(`cli.py:325`) uploads in order so it never trips this; the browser uploads
sequentially too, but any parallel or retried client will.

## Phases 1-17 — implementation plan

Ordered so each phase is independently testable. P0 done. Each block ends with the
tests that must pass before moving on.

### Phase 1 — Version single-sourcing (do this first; it unblocks packaging)

`__init__.py:3` is the canonical value. `app.py:50` and `devices.py:118` hold
independent `"0.1.0"` literals, and `pyproject.toml:7` is a fourth.

- Make `__init__.py` read the version from installed metadata with the literal as
  a fallback: `importlib.metadata.version("seltransfer")`, falling back to
  `"0.1.0"` when not installed (which is the frozen case, so the fallback must
  stay correct and must be asserted).
- Replace the literals in `app.py` and `devices.py` with `__version__`.
- Add `tests/test_version.py`: all four surfaces agree; the fallback is exercised
  by simulating a missing distribution.

### Phase 2 — Frozen-safe resource resolution

`app.py:114-115` derives asset paths from `__file__`. Under PyInstaller one-file,
`__file__` points into `sys._MEIPASS`, so this may work by accident but is not
guaranteed and gives a silent blank page if wrong.

- Add `seltransfer/resources.py` with `resource_root()` that returns
  `Path(sys._MEIPASS)` when frozen, else walks up from `__file__`, preferring an
  importable `seltransfer.web` package path. No hard-coded developer paths.
- Use it in `app.py` for both `static` and `templates`.
- Add `tests/test_resources.py` asserting the resolver returns a directory
  containing `index.html`, `style.css`, and `app.js` in the source tree, and
  returns `sys._MEIPASS` when `getattr(sys, "frozen", False)` is set.

### Phase 3 — Application data location

Move user data to the platform-correct location while preserving
`SELTRANSFER_APP_DIR`.

- `resolve_app_dir()` precedence: `SELTRANSFER_APP_DIR` > Windows
  `%LOCALAPPDATA%\SELTRANSFER` > `~/.seltransfer`. Use `platform.system()`,
  not the ignored `platform` hint. Respect `LOCALAPPDATA` being unset.
- `config.py:76-77` runs `mkdir` at import time. Move directory creation into a
  `ensure_app_dir()` called by `create_app`, so importing the module has no
  filesystem side effect. This also stops test collection from touching the real
  home directory.
- Add `tests/test_app_dir.py`: env override wins; Windows path shape under a
  patched `platform.system` and `LOCALAPPDATA`; POSIX fallback; import has no side
  effect.
- Update `test_transfers.py:18` which currently asserts the Android hint is
  ignored — keep that assertion, it is still correct.

### Phase 4 — Pairing codes (replaces unauthenticated pairing)

Fixes W1. The destination must prove intent with an out-of-band code, so this
works for a browser phone and a headless CLI peer alike.

- New `PairingCode`: `secrets.token_urlsafe` truncated to a short uppercase
  alphabet for easy manual entry (e.g. 8 chars, no `0/O/1/I/l` ambiguity),
  hashed at rest, single-use, 120 s TTL.
- Flow: requester calls `POST /api/devices/{id}/pair/request` -> a pending
  request is created. The destination surfaces the code (CLI prints it; the web UI
  shows it). The requester calls `POST /api/devices/{id}/pair/confirm` with the
  code. Only then is the device added to `paired_devices`.
- Pairings carry `paired_at` and expire; an expired pairing is rejected and the
  device must re-confirm.
- A browser session may pair without a code (the user is already looking at the
  device in its own UI and that is the explicit interaction); an unauthenticated
  caller must present a code. This keeps the common browser flow one click.
- Deprecate the old `POST /api/devices/{id}/pair` behaviour by requiring the code
  when there is no session, rather than deleting the route.
- Tests: wrong code, expired code, replayed code (second use rejected), code for
  the wrong device, unpaired caller cannot create a transfer, unpaired-by-expiry
  cannot create a transfer, pair/unpair round trip over HTTP, code never logged.

### Phase 5 — Caller identity (fixes W2)

Replace the "unauthenticated means local node" fallback with an explicit,
loopback-only local credential.

- Generate a per-process local token at `create_app` time, store it in
  `app.state.local_token`, and have the CLI read it from the same settings module
  (both run in the same process for `start`; for the separate `send`/`status`
  processes, write it to `<app_dir>/local.token` with restrictive permissions and
  read it there).
- `_caller()` becomes: valid browser session -> that device; else valid local
  token -> local node; else **no identity**, and the request is rejected with 401
  on anything that touches transfer state, history, or pairing.
- A LAN attacker with no token now gets 401 instead of inheriting local identity.
- Tests: unauthenticated history/accept/cancel/pause/resume all 401; the CLI
  happy path still works end to end (extend `test_phone_delivery.py`).

### Phase 6 — Bounded state and resource limits (fixes W3, W5, and part of W4)

- Evict expired browser sessions and WebRTC sessions on access, not just filter
  them. Add a periodic sweep in the lifespan so an idle server does not accumulate.
- Cap concurrent in-flight transfers per server and total stored transfers; evict
  the oldest terminal ones beyond the cap.
- Cap the number of pending incoming transfers an unauthenticated caller may
  create within a window, and reject once exceeded.
- Validate `IncomingTransfer.sender`: replace the bare `dict` with a model with
  bounded, validated fields (`device_id` matching `DEVICE_ID_PATTERN`,
  `name`/`display_name` length-bounded, no control characters).
- Apply `DEVICE_ID_PATTERN` to `IncomingTransfer.transfer_id` (fixes W5 log
  injection) and keep a strict pattern for every logged field.
- Add `tests/test_resource_limits.py`: session expiry removes entries; cap on
  concurrent transfers; cap on pending announcements; oversized/unknown-keyed
  sender metadata rejected; transfer_id with a newline or 10 KB is rejected.

### Phase 7 — Filesystem hardening (fixes W6, W7, W8)

- `safe_relative_path`: additionally reject Windows reserved device names
  (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, with or without an
  extension, case-insensitive), reject a segment that is all dots, and reject
  names that are only reserved characters after sanitising. Keep accepting
  legitimate nested paths.
- Replace the append-ordered `received_files` list with an index-keyed dict
  (`received_files[str(index)] -> path`) so out-of-order uploads map correctly, and
  make a repeat upload for an index idempotent instead of appending a second entry
  and double-counting `transferred_bytes` (fixes W7 and W8 together). Update the
  download route to read by key and re-verify the index range.
- Resolve and confirm every final path is inside `download_root` using
  `Path.is_relative_to` on the resolved path, not `root not in resolved.parents`.
- Tests: each reserved name rejected; nested `a/b/c.txt` accepted; out-of-order
  upload returns the right bytes for each index; duplicate upload does not change
  `transferred_bytes`; `..\..\` with a backslash rejected; UNC `\\server\share`
  rejected; `\\?\C:\x` rejected; null byte and control chars rejected.

### Phase 8 — HTTP hardening (fixes W9, W10, W11)

- Add `TrustedHostMiddleware` allowing only `localhost`, `127.0.0.1`, `[::1]`, and
  private/link-local literals plus the configured local address. This blocks DNS
  rebinding, where a public site resolves a rebinding domain to the LAN IP and
  drives the API from the user's browser.
- Add response headers: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a CSP that allows
  only same-origin scripts/styles and disallows inline script.
- Stop returning the absolute `download_directory` from `/api/connection` unless
  `SELTRANSFER_EXPOSE_PATHS=true`. The UI already handles a relative value.
- Return generic 500s with no path or traceback in the body; log the detail
  server-side at ERROR.
- Tests: rebinding Host header rejected; headers present on `/`; public origin
  still rejected; `/api/connection` hides the path by default and shows it when
  enabled; no traceback text in any 4xx/5xx body.

### Phase 9 — TLS plumbing (opt-in, real)

Per your decision: HTTP stays the default, but TLS genuinely works when enabled.

- Add `tls_certfile`, `tls_keyfile`, and `tls_enabled` settings.
- `start` passes `ssl_certfile`/`ssl_keyfile` to uvicorn when enabled, validates
  both exist and the key is readable before binding, and fails with a clear
  message if not.
- The QR code and the printed URL use `https://` when TLS is on, `http://`
  otherwise. `/api/connection` reports the scheme so the UI shows the right URL.
- Document that HTTP is plaintext, that a self-signed certificate will produce a
  browser warning, and that a trusted certificate is needed for a clean phone
  experience. Do not claim confidentiality we do not provide.
- Tests: settings round-trip; URL scheme switches; missing cert file produces a
  clear error and does not start a half-configured server.

### Phase 10 — Windows packaging

- `packaging/seltransfer.spec`: onedir (faster startup, easier to inspect) with
  `datas` for `web/templates/*.html` and `web/static/*`, `hiddenimports` for
  uvicorn's dynamic imports, and `excludes` for the dev/test stack
  (`pytest`, `httpx`, `PIL`, `tkinter`, `IPython`, `setuptools`).
  - Pillow is used only by `seltransfer/utils`, which nothing but `test_utils.py`
    imports; the CLI renders QR with `print_ascii`. So exclude it and drop
    `Pillow` from the runtime dependency set — but keep `qrcode[pil]` available
    for the source install so `test_utils.py` keeps passing.
- `packaging/build.ps1`: reproducible. Cleans `build/` and `dist/`, runs PyInstaller
  with the spec, then runs a post-build smoke test. No developer-specific paths;
  output to `dist/SELTRANSFER/`.
- `packaging/SELTRANSFER.py` shim: the console-script entry point PyInstaller needs
  (`seltransfer.cli:app` is a Typer object, not a plain function).
- CLI parity: all nine commands must be present in the exe. `status` and
  `discover` currently hardcode port 8765 and must read the configured port
  (fixes W14), otherwise a `--port 9000` server is invisible to them.
- Fix the firewall command (W12, W13): use the real program path
  (`sys.executable`, which is the exe itself when frozen) instead of
  `program=System`; make the rule name include the port so a second port is
  possible; check for an existing rule by name AND port; scope `remoteip` to
  `localsubnet`; add a `--remove` flag; keep the manual `netsh` hint on failure.
- `packaging/CLEAN_MACHINE_CHECKLIST.md`: the manual list, written down but
  explicitly not executed by me.
- `tests/test_packaging.py` additions: the spec file exists and parses, the spec
  references the web assets and excludes the dev stack, `sys.executable` is used
  in the firewall command, and the version is single-sourced in the built output.

### Phase 11 — Test isolation (fixes W17)

This should land before the new tests, so the new tests do not inherit the
problem.

- Add `tests/conftest.py` with an autouse fixture that sets `SELTRANSFER_APP_DIR`
  to a per-session `tmp_path` before any app is constructed, so no test touches
  the real `~/.seltransfer`.
- Point the existing duplicated `create_app` fixtures at a shared factory. This
  is a refactor of test code only, not a behaviour change.
- Add a guard test asserting `Path.home()/".seltransfer"` is not created by a test
  run.

### Phase 12 — Documentation and threat model

- `SECURITY.md`: the five attacker profiles, the trust assumptions, what is and is
  not protected, the HTTP plaintext statement, the TLS situation, and a reporting
  contact.
- `docs/THREAT_MODEL.md`: attacker -> capability -> existing control -> residual
  risk, in a table.
- README: add the executable install path, the `%LOCALAPPDATA%` data location,
  pairing codes, TLS configuration, the build instructions, and correct the
  "no secrets" claims to match what the code actually does.
- `docs/RELEASE_CHECKLIST.md`: the Phase 0 recording, the Phase 17 checklist, and
  the final report template.

## Files I expect to create

```text
packaging/seltransfer.spec
packaging/build.ps1
packaging/SELTRANSFER.py
packaging/CLEAN_MACHINE_CHECKLIST.md
src/seltransfer/resources.py
src/seltransfer/pairing.py
docs/THREAT_MODEL.md
docs/RELEASE_CHECKLIST.md
SECURITY.md
tests/conftest.py
tests/test_version.py
tests/test_resources.py
tests/test_app_dir.py
tests/test_pairing.py
tests/test_resource_limits.py
tests/test_filesystem.py
tests/test_http_hardening.py
tests/test_tls.py
```

## Files I expect to modify

```text
src/seltransfer/__init__.py        single version source
src/seltransfer/config.py          %LOCALAPPDATA%, no import-time mkdir, TLS settings
src/seltransfer/devices.py         version literal, pairing expiry, registry eviction
src/seltransfer/transfers.py       reserved names, index-keyed received files
src/seltransfer/server/app.py      resource resolution, TrustedHost, headers, limits
src/seltransfer/server/routes.py   pairing codes, caller identity, validated models,
                                   log-safe fields, path disclosure off, TLS scheme
src/seltransfer/cli.py             port-aware status/discover, firewall fixes, TLS flags
pyproject.toml                     single version, Pillow removal from runtime deps
tests/test_server.py               update for new auth + index-keyed files
tests/test_authorization.py        update for caller identity change
tests/test_phone_delivery.py       update for caller identity change
tests/test_packaging.py            spec/build assertions
README.md, .gitignore
```

## Explicitly not doing, and why

- **No default TLS.** A self-signed certificate on a QR-scanned LAN page produces
  a certificate warning on every phone connection, which is a worse first
  experience than plaintext on a hotspot the user chose. The plumbing is real and
  the switch is documented.
- **No installer framework.** The spec allows skipping it if it worsens
  maintenance. A `dist/SELTRANSFER/` folder plus a zip is more maintainable and
  avoids asking for admin rights. Revisit if asked.
- **No rewrite of the transfer path.** Only the identified bugs in
  `received_files` and reserved names change.
- **No new runtime dependencies.** Pairing uses `secrets`; rate/cap logic uses
  the standard library; the UI progress bar stays out of scope.

## Risks and how I will handle them

| Risk | Handling |
|---|---|
| Caller-identity change breaks the CLI `send` path | Implement the local-token file, then extend `test_phone_delivery.py` to cover the CLI flow before declaring done |
| Pairing codes add friction to the common one-click browser flow | Browser sessions pair without a code; only unauthenticated callers need one |
| Index-keyed `received_files` changes a type the tests touch | Update all call sites in the same commit; do not leave a compatibility shim |
| Test refactor changes 120 passing tests | The conftest and factory refactor must be a standalone, green step before new tests |
| PyInstaller build is slow and I cannot fully validate it | Automate what is automatable, and be explicit in the final report about what I could not verify |

## What I will not claim

I will not report a clean-machine validation, because I cannot perform one from
this environment. I will report exactly which automated packaging checks ran, and
hand you the manual checklist for a machine without Python.
