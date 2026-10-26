package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFwdParsing(t *testing.T) {
	env := []byte("PATH=/usr/bin\x00" + fwdVar + "=1\x00HOME=/root\x00")
	if !fwdFromEnv(env) {
		t.Error("NUL-separated environ with =1 should be on")
	}
	if fwdFromEnv([]byte(fwdVar + "=0\n")) {
		t.Error("=0 should be off")
	}
	for text, want := range map[string]bool{
		"[Service]\nEnvironment=" + fwdVar + "=1\n":         true,
		"[Service]\nEnvironment=\"" + fwdVar + "=true\"\n":  true,
		fwdVar + "=1\n" + fwdVar + "=0\n":                    false, // last wins
		"# " + fwdVar + "=1\n":                               false, // comment
		"FLAGS=\"\"\n":                                       false,
	} {
		if got := fwdFromConf(text); got != want {
			t.Errorf("fwdFromConf(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestClassifyFwd(t *testing.T) {
	cases := []struct {
		name   string
		st     fwdState
		ssh    string
		win    bool
		status string
	}{
		{"windows", fwdState{}, "on", true, "INFO"},
		{"active", fwdState{daemonFound: true, envRead: true, active: true}, "on", false, "PASS"},
		{"needs restart", fwdState{daemonFound: true, envRead: true, confFile: "/etc/default/tailscaled"}, "on", false, "WARN"},
		{"ssh on, not set", fwdState{daemonFound: true, envRead: true}, "on", false, "WARN"},
		{"ssh off", fwdState{daemonFound: true, envRead: true}, "off", false, "INFO"},
		{"ssh off, not root", fwdState{daemonFound: true}, "off", false, "INFO"},
		{"ssh off, no daemon", fwdState{}, "off", false, "INFO"},
		{"no daemon", fwdState{}, "on", false, "UNKNOWN"},
		{"not root", fwdState{daemonFound: true}, "on", false, "UNKNOWN"},
		{"ssh unknown", fwdState{daemonFound: true, envRead: true}, "unknown", false, "UNKNOWN"},
	}
	for _, c := range cases {
		f := classifyFwd(c.st, c.ssh, c.win)
		if f.Status != c.status {
			t.Errorf("%s: status %s, want %s", c.name, f.Status, c.status)
		}
		if f.Title == "" || (f.Status == "WARN" || f.Status == "UNKNOWN") && (f.Problem == "" || len(f.Steps) == 0) {
			t.Errorf("%s: incomplete explanation: %+v", c.name, f)
		}
	}
}

func TestReadFwdStateHook(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TAILGUARD_FWD_ROOT", root)
	os.WriteFile(filepath.Join(root, "environ"), []byte("PATH=/bin\n"), 0o644)
	d := filepath.Join(root, "etc", "systemd", "system", "tailscaled.service.d")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "50-x.conf"), []byte("[Service]\nEnvironment="+fwdVar+"=1\n"), 0o644)
	st := readFwdState()
	if !st.daemonFound || !st.envRead || st.active || st.confFile == "" {
		t.Errorf("want found+read, not active, conf set; got %+v", st)
	}
	if f := classifyFwd(st, "on", false); f.Status != "WARN" || f.Next == "" {
		t.Errorf("set-but-not-active should be a WARN with a next step, got %s", f.Status)
	}
}
