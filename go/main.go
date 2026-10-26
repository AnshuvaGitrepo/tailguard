// Command tailscale-audit is a read-only Tailscale security audit for the
// "Tailworm" findings (Cyberdione Labs, Oct 25 2026). It runs a fixed set of
// read-only tailscale CLI commands, optionally audits an exported policy
// file, and writes a .txt and .json report. It never changes any setting.
//
// Exit codes: 0 no FAIL, 1 at least one FAIL, 2 the tool itself errored.
//
// Test hooks (env): TAILGUARD_TAILSCALE=path to the tailscale binary,
// TAILGUARD_SCAN_ROOTS=list of folders (OS path-list separator) that
// replaces the auth-key search paths.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	toolVersion    = "1.1.1"
	minSafeVersion = "1.98.9"
)

// Finding is one result in the report. Check, Detail and Fix are the short
// technical form; Title, Problem, Why, Steps and MoreHelp are the plain-English
// explanation shown to people.
type Finding struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Check    string   `json:"check"`
	Detail   string   `json:"detail"`
	Fix      string   `json:"fix"`
	Title    string   `json:"title"`
	Problem  string   `json:"problem,omitempty"`
	Why      string   `json:"why,omitempty"`
	Steps    []string `json:"steps,omitempty"`
	MoreHelp string   `json:"more_help,omitempty"`
	Next     string   `json:"next_step,omitempty"` // short action for NEXT STEPS

	// Findings with the same Group are shown as one card, e.g. the
	// port-forwarding warning that applies to every SSH rule.
	Group string `json:"-"`
	Ref   string `json:"-"`
}

// Audit collects everything that goes into the report.
type Audit struct {
	Host       string
	Now        time.Time
	Elevated   bool
	PolicyFile string
	Local      []Finding
	Policy     *PolicyResult
	Todo       []string
}

// withFix fills the one-line Fix from the steps.
func withFix(f Finding) Finding {
	if f.Fix == "" {
		f.Fix = "-"
		if len(f.Steps) > 0 {
			var parts []string
			for i, s := range f.Steps {
				parts = append(parts, fmt.Sprintf("%d) %s", i+1, s))
			}
			f.Fix = strings.Join(parts, " ")
		}
	}
	return f
}

func (a *Audit) add(f Finding) {
	a.Local = append(a.Local, withFix(f))
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tailscale-audit: error: "+format+"\n", args...)
	os.Exit(2)
}

func usage() {
	fmt.Fprint(os.Stderr, `tailscale-audit - read-only Tailscale security audit

Usage: tailscale-audit [options]

Options:
  --policy FILE   Also audit an exported tailnet policy file (HuJSON)
  --no-color      Plain console output
  --out DIR       Where to write the .txt and .json reports
                  (default: the folder this program is in)
  --no-progress   Do not show the progress bar while scanning
  --help          Show this help

Exit codes: 0 no FAIL, 1 at least one FAIL, 2 tool error.
This tool only reads. It never changes any Tailscale setting.
`)
}

func main() {
	fs := flag.NewFlagSet("tailscale-audit", flag.ContinueOnError)
	fs.Usage = usage
	policyFile := fs.String("policy", "", "")
	noColor := fs.Bool("no-color", false, "")
	outDir := fs.String("out", "", "")
	noProgress := fs.Bool("no-progress", false, "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		usage()
		die("unexpected argument: %s", fs.Arg(0))
	}

	isConsole := enableColor()
	color := isConsole && !*noColor && os.Getenv("NO_COLOR") == ""
	width := 80
	if isConsole {
		width = min(max(consoleWidth()-1, 60), 100)
	}

	a := &Audit{Now: time.Now(), Elevated: isElevated()}
	a.Host, _ = os.Hostname()
	if a.Host == "" {
		a.Host = "unknown-host"
	}

	steps := 6
	if *policyFile != "" {
		steps++
	}
	prog := newProgress(!*noProgress, steps)

	runLocalChecks(a, prog)

	if *policyFile != "" {
		prog.Step("Auditing policy file")
		data, err := os.ReadFile(*policyFile)
		if err != nil {
			prog.Done()
			die("cannot read policy file: %v", err)
		}
		pr, err := auditPolicy(data)
		if err != nil {
			prog.Done()
			die("policy file is not valid HuJSON/JSON: %s: %v", *policyFile, err)
		}
		pr.File = *policyFile
		a.Policy = pr
		a.PolicyFile = *policyFile
	}
	a.Todo = nextSteps(a)
	prog.Done()

	fmt.Print(renderText(a, color, width))

	dir := *outDir
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			die("cannot find the program folder: %v", err)
		}
		dir = filepath.Dir(exe)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		die("cannot create output dir %s: %v", dir, err)
	}
	base := filepath.Join(dir, fmt.Sprintf("tailscale-audit-%s-%s", safeName(a.Host), a.Now.Format("2006-01-02")))
	if err := os.WriteFile(base+".txt", []byte(renderText(a, false, 80)), 0o644); err != nil {
		die("cannot write %s.txt (try --out DIR): %v", base, err)
	}
	js, err := renderJSON(a)
	if err != nil {
		die("cannot build JSON report: %v", err)
	}
	if err := os.WriteFile(base+".json", js, 0o644); err != nil {
		die("cannot write %s.json (try --out DIR): %v", base, err)
	}
	fmt.Printf("\nReport: %s.txt\n        %s.json\n", base, base)

	if counts(a)["FAIL"] > 0 {
		os.Exit(1)
	}
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func safeName(s string) string { return unsafeChars.ReplaceAllString(s, "_") }

func counts(a *Audit) map[string]int {
	c := map[string]int{"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0, "UNKNOWN": 0}
	for _, f := range a.Local {
		c[f.Status]++
	}
	if a.Policy != nil {
		for _, f := range a.Policy.Findings {
			c[f.Status]++
		}
	}
	return c
}

func osName() string { return runtime.GOOS }
