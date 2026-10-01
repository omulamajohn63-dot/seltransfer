# Clean-machine checklist

These are the checks that **cannot** be automated from the build machine, because
they need a Windows machine with no Python installed and a second device.

`packaging/build.ps1` runs everything that can be automated: the test suite, the
lint and type checks, a real PyInstaller build, the presence of the bundled web
assets, and `SELTRANSFER.exe version`, `--help`, `devices`, and `doctor`. Do the
rest here.

## Before you start

- [ ] A Windows machine with **no Python installed**, to prove the executable is
      genuinely self-contained. Check with `py -3 --version` in a fresh prompt.
- [ ] A phone on the same Wi-Fi, or the PC's own hotspot.
- [ ] `dist\SELTRANSFER\` copied across (or `dist\SELTRANSFER-*-windows-x64.zip`).

## 1. Launch

- [ ] `SELTRANSFER.exe` (no arguments) prints the help, or starts the server if
      double-clicked.
- [ ] Terminal shows the banner without any `` characters or mojibake.
- [ ] `SELTRANSFER.exe version` prints the same version as the source tree.

## 2. Server and QR

- [ ] `SELTRANSFER.exe start` reports a detected interface and an IP address.
- [ ] A QR code is drawn in the terminal.
- [ ] The printed URL matches the QR code, including the scheme.

## 3. Web interface

- [ ] The phone opens the page; no browser console errors.
- [ ] Styling loads, including **dark mode** if the phone is set to it.
- [ ] Keyboard tabbing on a PC shows a visible focus ring on every control.
- [ ] `http://<pc-ip>:<port>/docs` returns 404.

## 4. Firewall

- [ ] `SELTRANSFER.exe allow-firewall` succeeds from an Administrator prompt.
- [ ] The rule names the **executable path**, not `System`, and is scoped to the
      local subnet:
      `netsh advfirewall firewall show rule name="SELTRANSFER (TCP 8765)"`
- [ ] `SELTRANSFER.exe allow-firewall --remove` removes it.

## 5. Transfers

- [ ] **PC → phone**: select the phone, send a file, accept on the phone, the file
      arrives and opens.
- [ ] **Phone → PC**: on the phone, send a file to the PC and accept on the PC. It
      lands in `%LOCALAPPDATA%\SELTRANSFER\downloads\`.
- [ ] **PC → PC**: run SELTRANSFER on both, pair them, transfer a file.
- [ ] A folder transfer preserves the folder structure.
- [ ] A file with a non-ASCII name (for example `café.txt`) works.
- [ ] An unpaired device is refused. On the phone, selecting the PC offers
      **Request access**; on the PC the request appears in the pairing panel and
      **Approve** pairs it, after which sending works. Nothing is read out or typed
      in at any point.

## 6. Integrity and limits

- [ ] A file whose contents were altered in transit is rejected, not accepted.
- [ ] An oversized file is refused before anything is written to disk.
- [ ] After a failed upload, no `.part` file is left in the downloads directory.

## 7. Data location and restart

- [ ] `%LOCALAPPDATA%\SELTRANSFER\` contains `history.db`, `downloads\`,
      `device-id`, and `local.token`.
- [ ] **Nothing was written beside the executable.** Check the `dist\SELTRANSFER\`
      folder for a stray `history.db` or `downloads\`.
- [ ] `SELTRANSFER.exe history` shows the earlier transfers after a restart.
- [ ] Stopping and restarting keeps the same device identity in the device list.

## 8. Uninstall

- [ ] Delete the `dist\SELTRANSFER\` folder.
- [ ] Confirm nothing is left running; the `%LOCALAPPDATA%\SELTRANSFER` folder is
      the only remaining trace, and it can be deleted separately.

---

## Result

Record what you actually observed. If anything failed, say which step and what
was on screen — a packaging bug that only appears here is exactly the kind worth
catching before release.
