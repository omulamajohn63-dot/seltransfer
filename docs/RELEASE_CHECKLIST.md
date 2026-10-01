# Release checklist

Run through this before tagging a release. Steps marked **[auto]** are covered by
`packaging/build.ps1` or the test suite; steps marked **[manual]** need a person.

## 1. Pre-flight

- [ ] **[auto]** `python -m pytest -p no:warnings`
- [ ] **[auto]** `node tests/web/test_app.js`
- [ ] **[auto]** `python -m ruff check .`
- [ ] **[auto]** `python -m mypy src`
- [ ] No test was deleted or skipped to make the suite pass. New tests for every
      behaviour this change introduced.

## 2. Version

- [ ] **[auto]** `pyproject.toml` declares the version.
- [ ] **[auto]** `seltransfer version` matches it.
- [ ] **[auto]** `tests/test_version.py` passes, which fails if any module
      reintroduces its own version literal.

## 3. Build

- [ ] **[auto]** `packaging/build.ps1` completes without `--SkipTests`.
- [ ] **[auto]** Bundled web assets present in `dist\SELTRANSFER\_internal`.
- [ ] **[auto]** `SELTRANSFER.exe version` matches the source tree.
- [ ] **[auto]** `SELTRANSFER.exe` exposes all nine CLI commands.
- [ ] **[auto]** `SELTRANSFER.exe devices`, `--help`, and `doctor` run.
- [ ] **[manual]** `packaging/CLEAN_MACHINE_CHECKLIST.md` completed on a machine
      with no Python, with a second device.

## 4. Packaging security

- [ ] **[auto]** `tests/test_tls.py::test_no_certificate_is_shipped_with_the_project`
- [ ] **[auto]** `/docs`, `/redoc`, `/openapi.json` return 404 by default.
- [ ] **[auto]** No `.env`, key material, or test fixture in the bundle.
- [ ] **[auto]** `seltransfer allow-firewall` names the real executable and scopes
      the rule to `localsubnet`.
- [ ] **[manual]** The executable writes nothing beside itself; the data lives in
      `%LOCALAPPDATA%\SELTRANSFER`.

## 5. Claims match reality

- [ ] README does not say "encrypted" without TLS being configured.
- [ ] README does not say "secure" without saying what is *not* protected.
- [ ] `SECURITY.md` limitations still describe the code as built.
- [ ] Every documented setting exists in `config.py`, and vice versa.

## 6. Before publishing

- [ ] Update the changelog with the user-visible changes.
- [ ] Note any new limitation in `SECURITY.md` under "Out of scope".
- [ ] Confirm the release notes do not overstate clean-machine validation: the
      build being green is not the same as a phone having connected.

## Known-incomplete items, restated so they are not lost

- [ ] Per-IP rate limiting is not implemented; resource use is bounded instead.
- [ ] History rows are retained indefinitely.
- [ ] A spoofed incoming transfer shows a chosen sender name with no IP shown
      beside it.
- [ ] TLS is implemented but not the default, and is not a mitigation for a
      hostile network.
