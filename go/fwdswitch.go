package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TS_SSH_DISABLE_FORWARDING is read by tailscaled (ssh/tailssh: envknob
// "TS_SSH_DISABLE_FORWARDING") and checked before the policy in every TCP and
// Unix-socket forwarding callback. It is undocumented: a stopgap for Tailworm.
const fwdVar = "TS_SSH_DISABLE_FORWARDING"

// fwdState is what we could learn about the switch on this machine.
type fwdState struct {
	daemonFound bool   // a tailscaled process was found
	envRead     bool   // its environment could be read (needs root)
	active      bool   // the variable is true in that environment
	confFile    string // config file that sets it to true, "" if none
}

// fwdTruthy parses a value the way envknob does (strconv.ParseBool).
func fwdTruthy(v string) bool {
	b, err := strconv.ParseBool(strings.Trim(strings.TrimSpace(v), `"'`))
	return err == nil && b
}

// fwdFromEnv looks for the variable in NUL- or newline-separated KEY=VALUE text.
func fwdFromEnv(env []byte) bool {
	on := false
	for _, kv := range strings.FieldsFunc(string(env), func(r rune) bool { return r == 0 || r == '\n' }) {
		if k, v, ok := strings.Cut(kv, "="); ok && k == fwdVar {
			on = fwdTruthy(v)
		}
	}
	return on
}

// fwdFromConf returns whether a config file turns the switch on. Matches both
// "TS_SSH_DISABLE_FORWARDING=1" (/etc/default) and
// Environment="TS_SSH_DISABLE_FORWARDING=1" (systemd); the last setting wins.
func fwdFromConf(text string) bool {
	on := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, fwdVar+"="); i >= 0 {
			v := line[i+len(fwdVar)+1:]
			if j := strings.IndexAny(v, " \t\""); j >= 0 {
				v = v[:j]
			}
			on = fwdTruthy(v)
		}
	}
	return on
}

// readFwdState inspects the running tailscaled and its config files.
// TAILGUARD_FWD_ROOT (tests) replaces "/": ROOT/environ stands for the
// daemon's environment and config files are read under ROOT/etc/...
func readFwdState() fwdState {
	var st fwdState
	root := os.Getenv("TAILGUARD_FWD_ROOT")
	if root != "" {
		if _, err := os.Stat(root); err == nil {
			st.daemonFound = true
			if env, err := os.ReadFile(filepath.Join(root, "environ")); err == nil {
				st.envRead, st.active = true, fwdFromEnv(env)
			}
		}
	} else {
		procs, _ := filepath.Glob("/proc/[0-9]*/comm")
		for _, comm := range procs {
			name, err := os.ReadFile(comm)
			if err != nil || strings.TrimSpace(string(name)) != "tailscaled" {
				continue
			}
			st.daemonFound = true
			if env, err := os.ReadFile(filepath.Join(filepath.Dir(comm), "environ")); err == nil {
				st.envRead, st.active = true, fwdFromEnv(env)
			}
			break
		}
	}
	base := root
	if base == "" {
		base = string(filepath.Separator) // the real /etc, not a relative etc/
	}
	confs := []string{filepath.Join(base, "etc", "default", "tailscaled"), filepath.Join(base, "etc", "sysconfig", "tailscaled")}
	for _, dir := range []string{"etc", "run", "lib"} {
		m, _ := filepath.Glob(filepath.Join(base, dir, "systemd", "system", "tailscaled.service.d", "*.conf"))
		confs = append(confs, m...)
	}
	for _, c := range confs {
		if b, err := os.ReadFile(c); err == nil && fwdFromConf(string(b)) {
			st.confFile = c
		}
	}
	return st
}

// fwdSteps is the how-to for turning the switch on (Linux, systemd).
var fwdSteps = []string{
	"First make sure you have another way in (console or normal SSH) in case tailscaled doesn't come back.",
	"Create the file /etc/systemd/system/tailscaled.service.d/50-disable-ssh-forwarding.conf with two lines: [Service] and Environment=" + fwdVar + "=1",
	"Restart it: sudo systemctl daemon-reload && sudo systemctl restart tailscaled",
	"Note: this is an undocumented Tailscale setting (a stopgap until the fix ships). It blocks TCP and Unix-socket forwarding, not SSH agent forwarding.",
}

const fwdHelp = "https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go"

// classifyFwd turns the state into finding C13. ssh is "on", "off" or "unknown".
func classifyFwd(st fwdState, ssh string, windows bool) Finding {
	const check = "SSH forwarding off-switch"
	f := Finding{ID: "C13", Check: check}
	unk := func(detail, problem string, steps ...string) Finding {
		return Finding{ID: "C13", Status: "UNKNOWN", Check: check, Title: "Could not check the SSH forwarding off-switch",
			Detail: detail, Problem: problem, Steps: steps}
	}
	switch {
	case windows:
		f.Status, f.Title = "INFO", "SSH forwarding off-switch: not needed on Windows (no Tailscale SSH server)"
		f.Detail = "the Tailscale SSH server does not run on Windows"
	case st.envRead && st.active:
		f.Status, f.Title = "PASS", "SSH forwarding off-switch is on ("+fwdVar+")"
		f.Detail = "running tailscaled has " + fwdVar + " set to true"
	case st.envRead && st.confFile != "":
		f.Status, f.Title, f.Next = "WARN", "SSH forwarding off-switch is set but not active yet", "Restart tailscaled so the forwarding off-switch takes effect"
		f.Detail = "set in " + st.confFile + "; not in the running tailscaled's environment"
		f.Problem = "It is set in " + st.confFile + ", but the running tailscaled doesn't have it, so forwarding is still allowed."
		f.Why = "The setting only takes effect when tailscaled starts."
		f.MoreHelp = fwdHelp
		f.Steps = []string{fwdSteps[0], fwdSteps[2], "Run this check again to confirm."}
	case st.envRead && ssh == "on":
		f.Status, f.Title, f.Next = "WARN", "Tailscale SSH is on and SSH forwarding is allowed", "Turn on the SSH forwarding off-switch on this server"
		f.Detail = fwdVar + " not set in the running tailscaled"
		f.Problem = "This device accepts Tailscale SSH and nothing on the device blocks port forwarding through it."
		f.Why = "Tailworm uses SSH port forwarding to reach hidden services on the device and become root."
		f.MoreHelp = fwdHelp
		f.Steps = fwdSteps
	case ssh == "off": // nothing to forward through, whether or not tailscaled could be inspected
		f.Status, f.Title = "INFO", "SSH forwarding off-switch: not needed now (Tailscale SSH is off)"
		f.Detail = fwdVar + " not active"
		f.Problem = "If you ever turn Tailscale SSH on for this device, turn this switch on too."
	case !st.daemonFound:
		f = unk("tailscaled process not found", "The tailscaled process wasn't found, so its settings couldn't be read.",
			"Make sure tailscaled is running: sudo systemctl status tailscaled", "Then run this check again with sudo.")
	case !st.envRead:
		problem := "The running tailscaled's settings can only be read with admin rights."
		if st.confFile != "" {
			problem += " It is set in " + st.confFile + ", but whether tailscaled has picked it up is unknown."
		}
		f = unk("tailscaled environment not readable (not root)", problem, "Run this check again with sudo.")
	default: // switch not active, and whether Tailscale SSH is on is unknown
		f = unk(fwdVar+" not set; RunSSH unknown", "The forwarding off-switch isn't set, and the tool couldn't tell whether Tailscale SSH is on.",
			"Check by hand: tailscale debug prefs (look for RunSSH).", "If it is true, turn on the off-switch as described in the README.")
	}
	return f
}
