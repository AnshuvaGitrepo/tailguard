# Changelog

All dates are 2026. Version numbers are in `go/main.go` (`toolVersion`) and
`tailscale-audit.sh` (`TOOL_VERSION`).

## 1.1.1 (27 Oct): follow-up review fixes

- **Alpine/BusyBox false PASS fixed.** BusyBox's `timeout` doesn't exit 124 when the
  limit hits: it kills `grep` with TERM, so the shell sees 143. The `.sh` only
  checked for 124, so a key search cut short on Alpine could report "no keys
  found". Any exit code above 2 (`grep` only uses 0–2) now counts as unfinished
  (UNKNOWN). New test: a BusyBox-style fake `timeout` must give UNKNOWN. The
  1.1.0 script gave PASS with it.
- **C13 when Tailscale SSH is off** is now always INFO ("not needed"), even if the
  `tailscaled` process can't be found.
- **Scripts are executable in the repo** (they were stored without the executable flag, so `./tailscale-audit.sh` and the tests failed on a fresh Linux clone). The README now uses `sudo bash tailscale-audit.sh`, which also works on a downloaded file.
- **Port-forwarding card** gained a final step: you can ignore it if C13 shows PASS
  on every Linux server the SSH rules reach. The policy file can't see servers, so
  the warning always appears.

## 1.1.0 (27 Oct): fixes from an outside review

- **New check C13: SSH forwarding off-switch.** It looks for `TS_SSH_DISABLE_FORWARDING`
  in the running `tailscaled`'s environment (Linux, needs root) and in its config
  files. It tells apart "on", "set but tailscaled not restarted", "Tailscale SSH on
  without it", and "can't read". On Windows it's INFO, because the Tailscale SSH
  server doesn't run there. The variable is in Tailscale's source but undocumented,
  so the fix steps say it's a stopgap and that it doesn't block agent forwarding.
- **Softer port-forwarding wording.** "Can't be blocked from your policy" is now
  "isn't controlled by any documented policy setting". It notes the reported (but
  undocumented) hosted per-rule switch and points to C13.
- **Tag rule.** One source to one `tag:` is now a **WARN** ("make sure only one
  device has this tag") instead of a FAIL, so the fix example passes its own check.
  `*`, `autogroup:member`, `autogroup:tagged`, `group:` and multiple entries are
  still FAIL.
- **Auto-update unset.** When `AutoUpdate.Apply` is not set, the device follows
  the tailnet default, which is now read from `Self.CapMap` (`default-auto-update`).
  It reports on or off from that, or UNKNOWN if the default isn't reported,
  instead of saying "off".
- **Bash key scan time limit.** Each folder now stops after 60 s (via `timeout`),
  and an unfinished folder makes C10 UNKNOWN, matching the Go tool.
- **Tests.** A new `server` fixture, fake daemon environments, and Go unit tests for
  the off-switch logic (including "set but not restarted").

## 1.0.0 (26 Oct): first release, built in one session

**Initial build**
- `tailscale-audit.sh` (bash, jq/python3/awk JSON backends) and the Go tool
  (`tailscale-audit.exe`, `-arm64.exe`, `-linux-amd64`, stdlib only).
- 12 local checks (C01–C12), a policy audit for HuJSON policy files, `.txt` and
  `.json` reports, and exit codes 0/1/2.
- Tests: a fake tailscale CLI (bash + Go), risky/safe/unknown fixtures, and
  bad/mixed/good policies.

**Fixes found on the first real run**
- **Auth-key scan:** on Windows it ran out of time inside ProgramData but still
  reported PASS. It now searches small, high-value folders first, with 60 s per
  folder, and reports **UNKNOWN** if a folder doesn't finish and nothing was found.
- **Peer count:** "0 of 0 peers" was shown while Tailscale wasn't connected. It's
  now UNKNOWN unless `BackendState=Running`.
- **Test runner:** `local out=… args=(… $out)` read the variable before it was set.
  Shellcheck caught it.

**Progress bar**
- A live step bar on stderr. The `.exe` adds a spinner, the current folder, a
  file count and elapsed time.
- New `--no-progress` flag. The bar turns off automatically when output isn't a
  console.

**Plain-English report**
- Problems first: FIX NOW, REVIEW and COULD NOT CHECK, then ALL GOOD and FOR
  YOUR INFORMATION.
- Every problem card has a title, Problem, Why it matters, lettered How to fix
  steps, More help and Details.
- SSH rules are described in plain words. NEXT STEPS is a short action list.
- Bright colours and ASCII markers (`[X]` `[!]` `[?]` `[OK]` `[i]`). Text wraps to
  the console width; the `.txt` wraps at 80 columns.
- The port-forwarding warning is merged into one card. A broad
  `autogroup:self` rule is explained as lower risk.
- New JSON fields: `title`, `problem`, `why`, `steps`, `more_help`,
  `next_step`, and `summary` on SSH rules.
- New tests: every problem must have an explanation and steps. The `compare`
  mode checks that both tools use the same wording.

**Docs and release**
- This changelog, the logo, and an illustrated walkthrough
  (`docs/tailguard-guide.pdf`).
- Published as open source under the MIT licence. Test fake keys are now written
  at test time instead of being stored in the repo.
