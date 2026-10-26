<img src="docs/logo.svg" alt="tailguard logo" width="96" align="right">

# tailguard: Tailscale "Tailworm" audit tools

Two **read-only** tools that check a Tailscale node, and optionally your exported
access policy, for the risky configuration behind the "Tailworm" report
(Cyberdione Labs, Oct 25 2026: with Tailscale SSH plus port forwarding, one
compromised device can get root on every server its SSH rules reach). As of
Oct 2026 there is **no patch, CVE or bulletin**. The fixes are configuration changes.

> Independent open-source project by Anshuva. **Not affiliated with or endorsed by Tailscale Inc.**

## Download

Get the latest files from the **[Releases page](../../releases/latest)**:

| File | Use it on |
|---|---|
| `tailscale-audit.exe` | Windows x64: one file, no install, no DLLs |
| `tailscale-audit-arm64.exe` | Windows on ARM |
| `tailscale-audit.sh` | Linux: bash only (Debian/Ubuntu, RHEL/Fedora, Arch, Alpine) |
| `tailscale-audit-linux-amd64` | Linux: the same tool built from the Go source |

Both tools only read. They never change a Tailscale setting.

## What's in this repo

| Path | What it is |
|---|---|
| `tailscale-audit.sh` | The Linux script |
| `go/` | Go source (stdlib only, no dependencies); `go/cmd/fakets` is the fake CLI for tests |
| `tests/` | Fake tailscale CLI, fixtures, sample policies, `run-tests.sh`, `compare_output.py` |
| `build.sh` | Builds all binaries (needs Go) |
| `docs/` | Logo and the illustrated walkthrough PDF |
| `CHANGELOG.md` / `LICENSE` | Version history / MIT licence |

## Usage

```bash
sudo ./tailscale-audit.sh                          # local checks
sudo ./tailscale-audit.sh --policy policy.hujson   # + policy audit
./tailscale-audit.sh --no-color --out /tmp/reports
```

```powershell
# Run from an Administrator prompt for the full auth-key scan
.\tailscale-audit.exe
.\tailscale-audit.exe --policy .\policy.hujson --out .\reports
```

| Flag | Meaning |
|---|---|
| `--policy FILE` | Also audit an exported tailnet policy file (HuJSON: comments and trailing commas are fine) |
| `--no-color` | Plain console output (also honours `NO_COLOR`) |
| `--out DIR` | Where to write the reports (default: the tool's own folder) |
| `--no-progress` | Hide the progress bar |
| `--help` | Help |

**Progress:** while it runs, a one-line bar shows the current step, for example
`[##########------] 6/7 / Scanning for auth keys  0:42  | 18240 files`.
The `.exe` also shows a spinner and file count. The bar goes to the screen
only (stderr), is erased before the results print, and is turned off
automatically when output is redirected.

**Output:** written for people who aren't Tailscale experts. The console and
`tailscale-audit-<hostname>-<date>.txt` use the same layout:

1. **Result line**: how many problems to fix now, how many to review, and how
   many are OK.
2. **FIX NOW** `[X]` and **REVIEW** `[!]`: one card per problem, with a plain
   title, **Problem**, **Why it matters**, lettered **How to fix** steps with
   exact commands, a **More help** link, and a short technical **Details** line.
3. **COULD NOT CHECK** `[?]`: what couldn't be verified and how to check it by hand.
4. **ALL GOOD** `[OK]` and **FOR YOUR INFORMATION** `[i]`: one line each.
5. **YOUR SSH RULES, IN PLAIN WORDS**: each policy SSH rule as a sentence.
6. **NEXT STEPS**: a short numbered to-do list, most urgent first.

The markers are plain ASCII, so they still read correctly without colour. Colours
are bright, so they're readable on PowerShell's blue background. Text wraps to
the window width (the `.txt` wraps at 80 columns).

The `.json` report keeps the technical fields (`id`, `status`, `check`,
`detail`, `fix`) and adds the plain-English `title`, `problem`, `why`,
`steps`, `more_help` and `next_step`. SSH rules also get a `summary` sentence.

**Exit codes:** `0` no FAIL, `1` at least one FAIL, `2` the tool itself errored
(bad flag, unreadable or invalid policy file, cannot write report).

To get the policy file: admin console > Access controls > copy the whole editor
contents into `policy.hujson`. With headscale, use the policy file you configured.

## What it checks

Every check is **PASS / WARN / FAIL / INFO / UNKNOWN** with a one-line fix.
If a command or JSON field is missing, the result is **UNKNOWN**, never PASS.

| ID | Check | Result |
|---|---|---|
| C01 | Tailscale version | FAIL below 1.98.9; otherwise WARN (Tailworm unpatched) |
| C02 | Daemon running and logged in (`BackendState`) | FAIL if NeedsLogin/Stopped/unreachable |
| C03 | Tailscale SSH server on this node (`RunSSH`) | WARN if on |
| C04 | Control server (`ControlURL`) | WARN for custom/headscale: forwarding can't be turned off from the policy, so every SSH grant = root |
| C05 | Tailnet Lock (`tailscale lock status`) | FAIL if off |
| C06 | Node key expiry (`Self.KeyExpiry`) | WARN if disabled |
| C07 | Auto-updates (`AutoUpdate.Apply`; if unset, the tailnet default from `Self.CapMap`) | WARN if off; UNKNOWN if unset and the tailnet default isn't reported |
| C08 | `tailscale serve` Unix-socket targets (`unix:`) | FAIL |
| C09 | App connector (`AppConnector.Advertise`) | WARN; C09R subnet routes and C09E exit node as INFO |
| C10 | Auth keys (`tskey-`) stored on disk | WARN, key always masked to 10 chars |
| C11 | Peers advertising Tailscale SSH (`sshHostKeys`) | INFO (blast radius) |
| C12 | Running as root/Administrator | INFO, lists what was skipped |
| C13 | SSH forwarding off-switch (`TS_SSH_DISABLE_FORWARDING` on the running `tailscaled`) | Linux: PASS if active; WARN if Tailscale SSH is on without it, or if it's set in config but `tailscaled` wasn't restarted; UNKNOWN without root. Windows: INFO (no Tailscale SSH server) |

**About C13.** `TS_SSH_DISABLE_FORWARDING` is read by `tailscaled`
([`ssh/tailssh`](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go))
and checked before the policy in every TCP and Unix-socket forwarding path. It is
**undocumented**: a stopgap until the Tailworm fix ships. It does not block SSH
agent forwarding. The tool reads the running daemon's environment
(`/proc/<pid>/environ`, needs root) and the usual config files (`/etc/default/tailscaled`,
`/etc/sysconfig/tailscaled`, `tailscaled.service.d/*.conf`). To turn it on with
systemd (keep another way in first):

```bash
sudo mkdir -p /etc/systemd/system/tailscaled.service.d
printf '[Service]\nEnvironment=TS_SSH_DISABLE_FORWARDING=1\n' | sudo tee /etc/systemd/system/tailscaled.service.d/50-disable-ssh-forwarding.conf
sudo systemctl daemon-reload && sudo systemctl restart tailscaled
```

The only tailscale commands run are `version`, `status --json`, `debug prefs`,
`serve status --json` and `lock status`. The tests prove that no other command is called.

**Auth-key search paths.** Linux: `/etc` (including systemd units and cron),
`/lib|usr/lib/systemd/system`, `/var/spool/cron`, `/root`, `/usr/local/{bin,sbin}`,
`/opt/scripts`, and `/home/*` shell histories, rc files, `*.sh` and `bin/`.
Windows: `%ProgramData%` (6 levels), the user profile (5 levels), PowerShell
history, and `C:\Windows\System32\Tasks` (scheduled tasks; Administrator only).
Files over 2 MB and binary files are skipped. Both tools stop searching a folder
after 60 s (the `.sh` uses `timeout` where available), and Windows searches the
small, high-value places first. If a folder doesn't finish and no key was found,
C10 is UNKNOWN, not PASS.

### Policy audit (`--policy`)

- Lists every `ssh` rule with src, dst, users and action.
- **FAIL**: a broad rule. That means src or dst uses `*`, `autogroup:member`,
  `autogroup:tagged` or any `group:`, or has more than one entry on either
  side. Use single source-to-destination pairs.
- **WARN**: one source to one `tag:`. That's a single pair only if exactly one
  device has the tag, which the policy file can't show, so check it in the admin console.
- **WARN**: `users` includes `root`.
- **WARN**: `action: accept`. Use `check`.
- **WARN**: on every ssh rule, because no documented policy setting turns off
  port forwarding (see below).
- **WARN**: `tailscale.com/app-connectors` in `nodeAttrs` or `grants`.
- **WARN**: an allow-all ACL (`*` to `*:*`) or an allow-all grant (`*`/`*`/ip `*`).

**About port forwarding.** Tailscale's policy reference (kb/1337 policy syntax,
kb/1193 Tailscale SSH, checked 26–27 Oct 2026) documents no `ssh`-rule field that
disables port forwarding. The node protocol does carry per-rule flags
(`allowLocalPortForwarding` / `allowRemotePortForwarding` in `tailcfg.SSHAction`),
and reports say the hosted service can set them per rule, but that isn't
documented yet. The tool doesn't invent a field name. It warns, recommends treating
each SSH grant as root-equivalent, and points to the host-level off-switch (C13).
Where forwarding must be off and you don't want to rely on an undocumented switch,
use OpenSSH with `AllowTcpForwarding no` and `AllowStreamLocalForwarding no`.

## JSON parsing in the bash script

The script uses `jq` if present, then `python3`, then a built-in awk parser.
awk is part of every listed distro, including busybox on Alpine. All three
produce the same results; the tests run each backend. HuJSON comments and
trailing commas are stripped with awk before parsing.

## Building

```bash
./build.sh          # needs Go; CGO_ENABLED=0, -trimpath, stripped
```
Needs Go 1.22 or newer. Testing also uses shellcheck and, optionally, jq.

## Testing

```bash
bash tests/run-tests.sh sh awk        # bash script, awk parser
bash tests/run-tests.sh sh python     # bash script, python3 parser
bash tests/run-tests.sh sh jq         # bash script, jq parser
bash tests/run-tests.sh exe ./tailscale-audit.exe tests/fakets/tailscale.exe
bash tests/run-tests.sh compare ./tailscale-audit.exe tests/fakets/tailscale.exe  # same wording in both tools
(cd go && go vet ./... && go test ./...)
shellcheck tailscale-audit.sh tests/*.sh tests/fake-tailscale/tailscale
```
Expected: 140 passed for each of the four `sh`/`exe` runs, 7 for `compare`,
`go vet` and `go test` clean, and no shellcheck output.

Fixtures: `risky` (old version, SSH on, headscale, no lock, unix-socket serve,
app connector, exit node, fake keys written at test time, no forwarding switch),
`safe` (everything good), `unknown` (odd version string, missing `debug prefs` and
`serve` commands), and `server` (Linux server with Tailscale SSH on,
auto-update unset but on via the tailnet default, forwarding off-switch active).
Sample policies: `bad`, `mixed` and `good`. Expected results are in
`tests/expected.txt`. The tests also check:
- exit codes
- that no unexpected tailscale command runs
- that no key is printed unmasked
- that every problem has a plain title, an explanation and fix steps
- that both tools print the same wording (`compare` mode, using
  `tests/compare_output.py`)

**Test env hooks:** `TAILGUARD_TAILSCALE` (path to tailscale),
`TAILGUARD_SCAN_ROOTS` (replace the key-search paths), `TAILGUARD_FWD_ROOT`
(stands in for `/`: `ROOT/environ` is the daemon's environment, config files are read
under `ROOT/etc/...`), and `TAILGUARD_JSON` (bash only: `jq|python|awk`).

## Walkthrough

[`docs/tailguard-guide.pdf`](docs/tailguard-guide.pdf) is an illustrated 11-page guide.
It covers the problem, how the tools work, every check, testing, how to run them,
and an example result.

## License

MIT. See [LICENSE](LICENSE). Tailscale is a trademark of Tailscale Inc.
This project isn't affiliated with or endorsed by Tailscale.
