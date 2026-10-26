# Changelog

All dates are 2026. Version numbers are in `go/main.go` (`toolVersion`) and
`tailscale-audit.sh` (`TOOL_VERSION`).

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
