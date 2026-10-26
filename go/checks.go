package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// findTailscale returns the tailscale CLI path, or "" if not found.
func findTailscale() string {
	if p := os.Getenv("TAILGUARD_TAILSCALE"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	if runtime.GOOS == "windows" {
		for _, base := range []string{os.Getenv("ProgramFiles"), `C:\Program Files`} {
			if base == "" {
				continue
			}
			p := filepath.Join(base, "Tailscale", "tailscale.exe")
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// runTS runs one read-only tailscale command and returns stdout.
func runTS(ts string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, ts, args...)
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return out.Bytes(), fmt.Errorf("%s", strings.ReplaceAll(msg, "\n", " "))
	}
	return out.Bytes(), nil
}

func parseJSON(b []byte) (map[string]any, bool) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false
	}
	return m, true
}

// get walks nested objects; ok is false if any key is missing.
func get(m map[string]any, keys ...string) (any, bool) {
	var cur any = m
	for _, k := range keys {
		obj, isObj := cur.(map[string]any)
		if !isObj {
			return nil, false
		}
		v, ok := obj[k]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

var verRe = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)

// verLess reports whether version a < b (numeric x.y.z).
func verLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// OS-specific wording used in fix steps.
var (
	sudo        = "sudo "
	isWindows   = runtime.GOOS == "windows"
	restartHelp = "restart it: sudo systemctl restart tailscaled, and check the internet connection"
)

func init() {
	if isWindows {
		sudo = ""
		restartHelp = "restart it: open services.msc, right-click Tailscale, Restart, and check the internet connection"
	}
}

func unknown(id, check, title, detail, problem string, steps ...string) Finding {
	return Finding{ID: id, Status: "UNKNOWN", Check: check, Title: title, Detail: detail, Problem: problem, Steps: steps}
}

func prefsUnknown(id, check, title, field string) Finding {
	return unknown(id, check, title, "'tailscale debug prefs' failed or has no "+field,
		"This version of Tailscale did not report this setting, so the tool can't tell.",
		"Run this by hand and look for "+field+": tailscale debug prefs")
}

func runLocalChecks(a *Audit, prog *Progress) {
	ts := findTailscale()
	var skipped []string

	if ts == "" {
		for i := 0; i < 5; i++ {
			prog.Step("tailscale CLI not found, skipping")
		}
		a.add(Finding{ID: "C01", Status: "INFO", Check: "Tailscale installed", Title: "Tailscale was not found on this device, so only the file search ran",
			Detail: "tailscale CLI not found on PATH or in Program Files"})
		for _, c := range [][2]string{{"C02", "Daemon running and logged in"}, {"C03", "Tailscale SSH server"}, {"C04", "Control server"},
			{"C05", "Tailnet Lock"}, {"C06", "Node key expiry"}, {"C07", "Auto-updates"}, {"C08", "Serve Unix-socket targets"},
			{"C09", "App connector"}, {"C11", "Peers with Tailscale SSH"}} {
			a.add(unknown(c[0], c[1], "Skipped: "+c[1]+" (Tailscale not found)", "skipped: tailscale CLI not found",
				"The tailscale command could not be found.", "Install Tailscale, or put the tailscale command on PATH, then run this check again."))
		}
	} else {
		localTailscaleChecks(a, ts, prog)
	}

	// 10. auth keys on disk (works without the tailscale CLI too)
	prog.Step("Scanning for auth keys")
	hits, sk, incomplete := scanAuthKeys(a.Elevated, prog)
	skipped = append(skipped, sk...)
	const c10 = "Auth keys on disk"
	switch {
	case len(hits) > 0:
		a.add(Finding{ID: "C10", Status: "WARN", Check: c10, Title: "Tailscale login keys found saved in files", Next: "Revoke and delete the saved Tailscale login keys",
			Detail:   fmt.Sprintf("%d tskey- match(es), shown masked above", len(hits)),
			Problem:  fmt.Sprintf("%d Tailscale auth key(s) are saved in plain text in these files: %s", len(hits), strings.Join(hits, "; ")),
			Why:      "Anyone who can read these files can use the key to add their own device to your network.",
			MoreHelp: "https://tailscale.com/kb/1085/auth-keys",
			Steps: []string{"Revoke each key in the admin console: https://login.tailscale.com/admin/settings/keys",
				"Delete the key from the files listed above.",
				"Next time, use a one-off or ephemeral key, or keep keys in a password or secret manager."}})
	case len(incomplete) > 0:
		search := "sudo grep -rl 'tskey-' " + strings.Join(incomplete, " ")
		if isWindows {
			search = "Get-ChildItem '" + strings.Join(incomplete, "','") + "' -Recurse -File -ErrorAction SilentlyContinue | Select-String 'tskey-' -List | Select-Object Path"
		}
		a.add(unknown("C10", c10, "The search for saved login keys did not finish",
			"none found, but the scan did not finish in: "+strings.Join(incomplete, ", "),
			"No keys were found, but these folders were too big to search completely: "+strings.Join(incomplete, ", "),
			"Search them by hand (this can take a while): "+search,
			"If it finds anything other than this tool's own test files, revoke and delete those keys."))
	default:
		a.add(Finding{ID: "C10", Status: "PASS", Check: c10, Title: "No Tailscale login keys found saved in files",
			Detail: "no tskey- strings found in the searched paths"})
	}

	// 12. privileges
	const c12 = "Running with admin rights"
	if a.Elevated {
		a.add(Finding{ID: "C12", Status: "INFO", Check: c12, Title: "Ran with admin rights, so every location was checked", Detail: "elevated: yes"})
	} else {
		s := strings.Join(skipped, ", ")
		if s == "" {
			s = "nothing"
		}
		how := "Run it again with sudo for a complete check."
		if isWindows {
			how = "Run it again from an Administrator PowerShell for a complete check."
		}
		a.add(Finding{ID: "C12", Status: "INFO", Check: c12, Title: "Ran without admin rights, so some places could not be searched",
			Detail: "elevated: no; skipped: " + s, Problem: how})
	}
	sortLocal(a)
}

// sortLocal keeps findings in check order (C01..C12).
func sortLocal(a *Audit) {
	sort.SliceStable(a.Local, func(i, j int) bool { return a.Local[i].ID[:3] < a.Local[j].ID[:3] })
}

func localTailscaleChecks(a *Audit, ts string, prog *Progress) {
	// 1. version
	prog.Step("Checking Tailscale version")
	const c1 = "Tailscale version"
	if out, err := runTS(ts, "version"); err != nil {
		a.add(unknown("C01", c1, "Could not read the Tailscale version", "'tailscale version' failed: "+err.Error(),
			"The 'tailscale version' command failed.", "Run it by hand and check the version is "+minSafeVersion+" or newer: tailscale version"))
	} else {
		first := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		ver := first
		if f := strings.Fields(first); len(f) > 0 {
			ver = f[0]
		}
		ver = strings.SplitN(ver, "-", 2)[0]
		switch {
		case !verRe.MatchString(ver):
			a.add(unknown("C01", c1, "Could not read the Tailscale version", "could not parse version from: "+first,
				"The tool did not understand the version text: "+first, "Run it by hand and check the version is "+minSafeVersion+" or newer: tailscale version"))
		case verLess(ver, minSafeVersion):
			a.add(Finding{ID: "C01", Status: "FAIL", Check: c1, Title: "Tailscale is out of date (version " + ver + ")", Next: "Update Tailscale to " + minSafeVersion + " or newer",
				Detail:   fmt.Sprintf("version %s < %s (TS-2026-009 and other SSH fixes)", ver, minSafeVersion),
				Problem:  "This version is older than " + minSafeVersion + " and has known Tailscale SSH security bugs that are already fixed in newer versions.",
				Why:      "These bugs are public, so attackers know how to use them against old versions.",
				MoreHelp: "https://tailscale.com/kb/1067/update",
				Steps: []string{"Update Tailscale now: " + sudo + "tailscale update (or update it from the Tailscale app or your package manager).",
					"Turn on automatic updates so it stays current: " + sudo + "tailscale set --auto-update"}})
		default:
			a.add(Finding{ID: "C01", Status: "WARN", Check: c1, Title: "Tailscale is up to date, but the \"Tailworm\" problem has no fix yet", Next: "Keep automatic updates on and watch for the Tailworm fix",
				Detail:   "version " + ver + "; Tailworm (Oct 25 2026) is unpatched",
				Problem:  "Version " + ver + " is fine, but the Tailworm security problems published on 25 Oct 2026 are not fixed in any Tailscale version yet.",
				Why:      "Until a fix is released, your settings are the only protection. The other items in this report are those settings.",
				MoreHelp: "https://tailscale.com/security-bulletins",
				Steps: []string{"Fix the other problems in this report.",
					"Keep automatic updates on, so the fix installs as soon as it is released.",
					"Check https://tailscale.com/security-bulletins for news of the fix."}})
		}
	}

	// status --json is used by checks 2, 6, 11
	var status map[string]any
	prog.Step("Reading tailscale status")
	statusOut, statusErr := runTS(ts, "status", "--json")
	statusOK := false
	if statusErr == nil {
		status, statusOK = parseJSON(statusOut)
	}
	backend := ""
	selfOK := false
	if statusOK {
		if v, ok := status["BackendState"].(string); ok {
			backend = v
		}
		_, selfOK = status["Self"].(map[string]any)
	}

	// 2. daemon
	const c2 = "Daemon running and logged in"
	again := "Run this check again."
	switch {
	case !statusOK:
		why := "did not return JSON"
		if statusErr != nil {
			why = "failed: " + statusErr.Error()
		}
		steps := []string{"Start it: sudo systemctl enable --now tailscaled", "Log in: sudo tailscale up", again}
		if isWindows {
			steps = []string{"Open the Tailscale app (Start menu or the tray icon) and click Connect.",
				"If it will not start: open services.msc, right-click Tailscale, Start.", again}
		}
		a.add(Finding{ID: "C02", Status: "FAIL", Check: c2, Title: "Tailscale is not running", Next: "Start Tailscale and log in",
			Detail: "'tailscale status --json' " + why, Problem: "The Tailscale service is not running, or the tool could not talk to it.",
			Why: "Most of the other checks could not be done.", Steps: steps})
	case backend == "Running":
		a.add(Finding{ID: "C02", Status: "PASS", Check: c2, Title: "Tailscale is running and logged in", Detail: "BackendState=Running"})
	case backend == "NeedsLogin" || backend == "NeedsMachineAuth":
		a.add(Finding{ID: "C02", Status: "FAIL", Check: c2, Title: "Tailscale is not logged in", Next: "Log in to Tailscale",
			Detail: "BackendState=" + backend, Problem: "This device is not logged in to your Tailscale network (or is waiting for approval).",
			Why:   "Most of the other checks could not be done.",
			Steps: []string{"Log in: " + sudo + "tailscale up (or log in from the Tailscale app).", "If it waits for approval, approve the device in the admin console.", again}})
	case backend == "Stopped":
		a.add(Finding{ID: "C02", Status: "FAIL", Check: c2, Title: "Tailscale is turned off (disconnected)", Next: "Connect Tailscale",
			Detail: "BackendState=Stopped", Problem: "Tailscale is installed but disconnected.",
			Why:   "Most of the other checks could not be done.",
			Steps: []string{"Connect: " + sudo + "tailscale up (or click Connect in the Tailscale app).", again}})
	case backend == "Starting" || backend == "NoState":
		a.add(Finding{ID: "C02", Status: "WARN", Check: c2, Title: "Tailscale is still connecting", Next: "Wait for Tailscale to connect, then run this check again",
			Detail: "BackendState=" + backend, Problem: "Tailscale has started but is not connected yet, so a few checks could not be finished.",
			Why:   "Those checks show up under COULD NOT CHECK.",
			Steps: []string{"Wait a minute, then run this check again.", "If it stays like this, " + restartHelp + "."}})
	default:
		a.add(unknown("C02", c2, "Could not tell whether Tailscale is connected", "BackendState="+backend,
			"Tailscale reported an unexpected state: "+backend, "Check it by hand: tailscale status"))
	}

	// prefs are used by checks 3, 4, 7, 9
	var prefs map[string]any
	prefsOK := false
	prog.Step("Reading node settings")
	if out, err := runTS(ts, "debug", "prefs"); err == nil {
		prefs, prefsOK = parseJSON(out)
	}
	pref := func(keys ...string) (any, bool) {
		if !prefsOK {
			return nil, false
		}
		return get(prefs, keys...)
	}

	// 3. Tailscale SSH server
	const c3 = "Tailscale SSH server"
	if v, ok := pref("RunSSH"); !ok || (v != true && v != false) {
		a.add(prefsUnknown("C03", c3, "Could not check whether Tailscale SSH is on", "RunSSH"))
	} else if v == true {
		a.add(Finding{ID: "C03", Status: "WARN", Check: c3, Title: "Tailscale SSH is turned on for this device", Next: "Turn off Tailscale SSH on this device if you don't need it",
			Detail:   "RunSSH=true",
			Problem:  "Other devices in your network can open a remote command line on this device through Tailscale SSH.",
			Why:      "This is exactly what the Tailworm attack uses: one hacked device can take full (root) control of this one, then move on to the next.",
			MoreHelp: "https://tailscale.com/kb/1193/tailscale-ssh",
			Steps: []string{"First make sure you have another way in (sitting at it, or normal SSH).",
				"If you don't use Tailscale SSH to reach this device, turn it off: " + sudo + "tailscale set --ssh=false",
				"If you need it, keep the SSH rules in your policy as narrow as possible (one person to this one device)."}})
	} else {
		a.add(Finding{ID: "C03", Status: "PASS", Check: c3, Title: "Tailscale SSH is turned off on this device", Detail: "RunSSH=false"})
	}

	// 4. control server
	const c4 = "Control server"
	headscale := false
	if v, ok := pref("ControlURL"); !ok {
		a.add(prefsUnknown("C04", c4, "Could not check which control server is used", "ControlURL"))
	} else {
		raw := str(v)
		host := ""
		if u, err := url.Parse(raw); err == nil {
			host = u.Hostname()
		}
		if raw == "" || raw == "null" || host == "controlplane.tailscale.com" || host == "login.tailscale.com" {
			a.add(Finding{ID: "C04", Status: "PASS", Check: c4, Title: "Managed by Tailscale's official service", Detail: "ControlURL=" + raw})
		} else {
			headscale = true
			a.add(Finding{ID: "C04", Status: "WARN", Check: c4, Title: "Managed by a self-hosted server (headscale?)", Next: "Treat every SSH permission as full admin access (headscale)",
				Detail:  "ControlURL=" + raw,
				Problem: "This device is managed by " + raw + ", not by Tailscale's own service.",
				Why:     "On headscale, SSH port forwarding can't be turned off, so anyone allowed to SSH into a device can become its administrator (root).",
				Steps: []string{"Treat every SSH permission in your policy as full admin access.",
					"Allow SSH only from one person or device to one server at a time.",
					"For important servers, turn off Tailscale SSH and use normal OpenSSH with 'AllowTcpForwarding no' and 'AllowStreamLocalForwarding no' in sshd_config."}})
		}
	}

	// 5. Tailnet Lock
	prog.Step("Checking Tailnet Lock")
	const c5 = "Tailnet Lock"
	if out, err := runTS(ts, "lock", "status"); err != nil {
		a.add(unknown("C05", c5, "Could not check Tailnet Lock", "'tailscale lock status' failed: "+err.Error(),
			"The 'tailscale lock status' command failed.", "Run it by hand: tailscale lock status"))
	} else {
		low := strings.ToLower(string(out))
		switch {
		case strings.Contains(low, "not enabled"):
			steps := []string{"On 2 or more devices you trust, run: tailscale lock status, and copy the 'tlpub:...' key it shows.",
				"On one of them, run: tailscale lock init --gen-disablements 1 --confirm tlpub:KEY1 tlpub:KEY2",
				"Save the 'disablement secret' it prints somewhere safe and offline. It is the only way to switch the lock off in an emergency.",
				"From then on, approve new devices with: tailscale lock sign"}
			if headscale {
				steps = append(steps, "Note: headscale may not support Tailnet Lock.")
			}
			a.add(Finding{ID: "C05", Status: "FAIL", Check: c5, Title: "Tailnet Lock is turned off", Next: "Turn on Tailnet Lock",
				Detail:   "tailscale lock status: Tailnet Lock is NOT enabled",
				Problem:  "If someone gets into your Tailscale account (or Tailscale's servers), they can add their own device to your network, and your devices will trust it.",
				Why:      "The Tailworm attack needs only one bad device inside your network to spread to the others.",
				MoreHelp: "https://tailscale.com/kb/1226/tailnet-lock", Steps: steps})
		case strings.Contains(low, "lock is enabled"):
			a.add(Finding{ID: "C05", Status: "PASS", Check: c5, Title: "Tailnet Lock is turned on", Detail: "Tailnet Lock is enabled"})
		default:
			first := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
			a.add(unknown("C05", c5, "Could not check Tailnet Lock", "unrecognised output: "+first,
				"The tool did not understand the output: "+first, "Run it by hand: tailscale lock status"))
		}
	}

	// 6. key expiry
	const c6 = "Node key expiry"
	notRunning := "Tailscale must be connected to check this (current state: " + orNone(backend) + ")."
	if statusOK && selfOK && backend == "Running" {
		if v, ok := get(status, "Self", "KeyExpiry"); ok && v != nil {
			date := str(v)
			if t, err := time.Parse(time.RFC3339, date); err == nil {
				date = t.Format("2 Jan 2006")
			}
			a.add(Finding{ID: "C06", Status: "PASS", Check: c6, Title: "This device's login expires normally (next: " + date + ")", Detail: "KeyExpiry=" + str(v)})
		} else {
			a.add(Finding{ID: "C06", Status: "WARN", Check: c6, Title: "This device's login never expires", Next: "Turn key expiry back on for this device",
				Detail:   "no Self.KeyExpiry while Running",
				Problem:  "Key expiry is turned off for this device, so it stays in your network forever, even if it is lost or stolen.",
				Why:      "A stolen or hacked device keeps its access until someone removes it by hand.",
				MoreHelp: "https://tailscale.com/kb/1028/key-expiry",
				Steps: []string{"Open https://login.tailscale.com/admin/machines",
					"Find this device, click its ... menu and choose 'Enable key expiry'."}})
		}
	} else {
		a.add(unknown("C06", c6, "Could not check whether this device's login expires", "state: "+orNone(backend),
			notRunning, "Connect Tailscale, then run this check again."))
	}

	// 7. auto-updates
	const c7 = "Auto-updates"
	if v, ok := pref("AutoUpdate", "Apply"); !ok {
		a.add(prefsUnknown("C07", c7, "Could not check automatic updates", "AutoUpdate.Apply"))
	} else if v == true {
		a.add(Finding{ID: "C07", Status: "PASS", Check: c7, Title: "Automatic updates are on", Detail: "AutoUpdate.Apply=true"})
	} else {
		a.add(Finding{ID: "C07", Status: "WARN", Check: c7, Title: "Automatic updates are off", Next: "Turn on automatic updates",
			Detail:   "AutoUpdate.Apply=" + str(v),
			Problem:  "Tailscale will not install security fixes by itself.",
			Why:      "When the Tailworm fix is released, this device stays unprotected until someone updates it by hand.",
			MoreHelp: "https://tailscale.com/kb/1067/update",
			Steps:    []string{"Turn on automatic updates: " + sudo + "tailscale set --auto-update"}})
	}

	// 8. serve Unix-socket targets
	prog.Step("Checking tailscale serve")
	const c8 = "Serve Unix-socket targets"
	if out, err := runTS(ts, "serve", "status", "--json"); err != nil {
		a.add(unknown("C08", c8, "Could not check what 'tailscale serve' shares", "'tailscale serve status --json' failed: "+err.Error(),
			"The 'tailscale serve status' command failed.", "Run it by hand: tailscale serve status"))
	} else {
		seen := map[string]bool{}
		var socks []string
		for _, m := range regexp.MustCompile(`"(unix:[^"]*)"`).FindAllSubmatch(out, -1) {
			s := string(m[1])
			if !seen[s] {
				seen[s] = true
				socks = append(socks, s)
			}
		}
		sort.Strings(socks)
		if len(socks) > 0 {
			a.add(Finding{ID: "C08", Status: "FAIL", Check: c8, Title: "'tailscale serve' is sharing a local system socket", Next: "Remove the socket share from 'tailscale serve'",
				Detail:   "serve targets: " + strings.Join(socks, " "),
				Problem:  "This device shares " + strings.Join(socks, ", ") + " with your network through 'tailscale serve'.",
				Why:      "System sockets (like docker.sock) give full control of the device, and the Tailworm report shows these shares can be abused.",
				MoreHelp: "https://tailscale.com/kb/1312/serve",
				Steps: []string{"See what is shared: tailscale serve status",
					"Remove all shares: " + sudo + "tailscale serve reset (or remove just that one share)."}})
		} else {
			a.add(Finding{ID: "C08", Status: "PASS", Check: c8, Title: "No risky 'tailscale serve' shares", Detail: "no unix: targets"})
		}
	}

	// 9. app connector, subnet routes, exit node
	const c9 = "App connector"
	if v, ok := pref("AppConnector", "Advertise"); !ok {
		a.add(prefsUnknown("C09", c9, "Could not check whether this device is an app connector", "AppConnector.Advertise"))
	} else if v == true {
		a.add(Finding{ID: "C09", Status: "WARN", Check: c9, Title: "This device is an app connector", Next: "Turn off the app connector if you don't need it",
			Detail:   "AppConnector.Advertise=true",
			Problem:  "This device routes traffic to outside apps or websites for the rest of your network.",
			Why:      "The Tailworm report says app connectors can be used to get around your access rules.",
			MoreHelp: "https://tailscale.com/kb/1281/app-connectors",
			Steps: []string{"If you don't need it, turn it off: " + sudo + "tailscale set --advertise-connector=false",
				"Also remove app connector settings you don't use from your policy file."}})
	} else {
		a.add(Finding{ID: "C09", Status: "PASS", Check: c9, Title: "This device is not an app connector", Detail: "AppConnector.Advertise=" + str(v)})
	}
	if v, ok := pref("AdvertiseRoutes"); ok {
		var subnets []string
		exit := false
		if list, isList := v.([]any); isList {
			for _, r := range list {
				s := str(r)
				if s == "0.0.0.0/0" || s == "::/0" {
					exit = true
				} else {
					subnets = append(subnets, s)
				}
			}
		}
		if len(subnets) > 0 {
			a.add(Finding{ID: "C09R", Status: "INFO", Check: "Subnet routes", Title: "Shares these local networks with your tailnet: " + strings.Join(subnets, ", "),
				Detail: "AdvertiseRoutes", Problem: "Devices allowed by your policy can reach these networks through this device."})
		} else {
			a.add(Finding{ID: "C09R", Status: "INFO", Check: "Subnet routes", Title: "Does not share any local networks (subnet routes)", Detail: "AdvertiseRoutes: none"})
		}
		if exit {
			a.add(Finding{ID: "C09E", Status: "INFO", Check: "Exit node", Title: "Is an exit node (other devices can send their internet traffic through it)", Detail: "AdvertiseRoutes has 0.0.0.0/0"})
		} else {
			a.add(Finding{ID: "C09E", Status: "INFO", Check: "Exit node", Title: "Is not an exit node", Detail: "no 0.0.0.0/0 route"})
		}
	} else {
		a.add(prefsUnknown("C09R", "Subnet routes", "Could not check shared networks or exit node", "AdvertiseRoutes"))
	}

	// 11. blast radius (the peer list is only complete while Running)
	const c11 = "Peers with Tailscale SSH"
	if statusOK && selfOK && backend == "Running" {
		peers, _ := status["Peer"].(map[string]any)
		var names []string
		for k, p := range peers {
			pm, _ := p.(map[string]any)
			if keys, _ := pm["sshHostKeys"].([]any); len(keys) > 0 {
				n, _ := pm["HostName"].(string)
				if n == "" {
					n = k
				}
				names = append(names, n)
			}
		}
		sort.Strings(names)
		f := Finding{ID: "C11", Status: "INFO", Check: c11,
			Title:  fmt.Sprintf("%d of your %d other devices accept Tailscale SSH", len(names), len(peers)),
			Detail: fmt.Sprintf("%d of %d peers have sshHostKeys", len(names), len(peers))}
		if len(names) > 0 {
			f.Problem = "These are the devices an attacker could try to reach with Tailworm: " + strings.Join(names, ", ") +
				". Turn off Tailscale SSH on any that don't need it (" + "tailscale set --ssh=false on that device)."
		} else {
			f.Problem = "None of your other devices accept Tailscale SSH, so Tailworm has nothing to attack from here right now."
		}
		a.add(f)
	} else {
		a.add(unknown("C11", c11, "Could not count devices that accept Tailscale SSH", "state: "+orNone(backend),
			notRunning, "Connect Tailscale, then run this check again."))
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
