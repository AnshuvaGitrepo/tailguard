// Command fakets is a fake tailscale CLI for tests. It serves canned output
// from $FAKE_TS_DIR (one of tests/fixtures/*). A missing fixture file makes
// the command fail, like an old CLI without that subcommand. Every call is
// appended to $FAKE_TS_LOG so tests can prove the audit only reads.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	dir := os.Getenv("FAKE_TS_DIR")
	if dir == "" {
		fmt.Fprintln(os.Stderr, "set FAKE_TS_DIR to a fixtures folder")
		os.Exit(2)
	}
	args := strings.Join(os.Args[1:], " ")
	if log := os.Getenv("FAKE_TS_LOG"); log != "" {
		if f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintln(f, args)
			f.Close()
		}
	}
	files := map[string]string{
		"version":             "version.txt",
		"status --json":       "status.json",
		"debug prefs":         "prefs.json",
		"serve status --json": "serve.json",
		"lock status":         "lock.txt",
	}
	name, ok := files[args]
	if !ok {
		fmt.Fprintln(os.Stderr, "fake tailscale: refusing unexpected command:", args)
		os.Exit(99)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fmt.Fprintln(os.Stderr, "tailscale: unknown subcommand or not available")
		os.Exit(1)
	}
	os.Stdout.Write(data)
}
