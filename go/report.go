package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Bright colours read well on both black and PowerShell-blue backgrounds.
const (
	cFail = "\033[91m"
	cWarn = "\033[93m"
	cPass = "\033[92m"
	cInfo = "\033[96m"
	cUnk  = "\033[95m"
	cBold = "\033[1m"
	cOff  = "\033[0m"
)

// Plain-ASCII markers, so the meaning survives without colour or Unicode.
var marker = map[string]string{"FAIL": "[X]", "WARN": "[!]", "UNKNOWN": "[?]", "PASS": "[OK]", "INFO": "[i]"}

// cards returns all findings (local, then policy) with grouped findings
// merged into one, e.g. one port-forwarding card listing every SSH rule.
func cards(a *Audit) []Finding {
	all := append([]Finding{}, a.Local...)
	if a.Policy != nil {
		all = append(all, a.Policy.Findings...)
	}
	var out []Finding
	at := map[string]int{}
	for _, f := range all {
		if f.Group == "" {
			out = append(out, f)
			continue
		}
		if i, ok := at[f.Group]; ok {
			out[i].Ref += ", " + strings.TrimPrefix(f.Ref, "SSH rule ")
			continue
		}
		at[f.Group] = len(out)
		out = append(out, f)
	}
	for i := range out {
		if out[i].Ref != "" {
			out[i].Title += " (" + strings.Replace(out[i].Ref, "SSH rule", "SSH rules", 1) + ")"
			if !strings.Contains(out[i].Ref, ",") {
				out[i].Title = strings.Replace(out[i].Title, "SSH rules", "SSH rule", 1)
			}
		}
	}
	return out
}

func byStatus(cs []Finding, status string) []Finding {
	var out []Finding
	for _, f := range cs {
		if f.Status == status {
			out = append(out, f)
		}
	}
	return out
}

// nextSteps is the short numbered to-do list at the end of the report.
func nextSteps(a *Audit) []string {
	cs := cards(a)
	var steps []string
	n := 0
	for _, st := range []string{"FAIL", "WARN"} {
		for _, f := range byStatus(cs, st) {
			n++
			do := f.Next
			if do == "" {
				do = f.Title
			}
			steps = append(steps, fmt.Sprintf("%s (see %d)", do, n))
		}
	}
	if len(byStatus(cs, "UNKNOWN")) > 0 {
		steps = append(steps, "Look at the COULD NOT CHECK items and check them by hand")
	}
	if a.Policy == nil {
		steps = append(steps, "Also check your access rules: copy your policy from the admin console (Access controls > JSON editor) into a file and run this tool with --policy FILE")
	}
	if len(steps) > 0 {
		steps = append(steps, "When you are done, run this check again to confirm everything is fixed")
	}
	return steps
}

// wrapLines splits text into lines of at most w1 (first) and w2 (rest)
// characters, breaking at spaces. A single long word gets its own line.
func wrapLines(text string, w1, w2 int) []string {
	var lines []string
	line, w := "", w1
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= w:
			line += " " + word
		default:
			lines = append(lines, line)
			line, w = word, w2
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

type textOut struct {
	b     strings.Builder
	color bool
	width int
}

func (t *textOut) col(code string) string {
	if t.color {
		return code
	}
	return ""
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// visLen is the on-screen length of s, ignoring colour codes.
func visLen(s string) int { return len(ansi.ReplaceAllString(s, "")) }

// para writes text after prefix, wrapping with continuation lines indented
// to the width of indent. code colours the text (not the prefix).
func (t *textOut) para(prefix, indent, text, code string) {
	lines := wrapLines(text, t.width-visLen(prefix), t.width-visLen(indent))
	for i, l := range lines {
		p := indent
		if i == 0 {
			p = prefix
		}
		fmt.Fprintf(&t.b, "%s%s%s%s\n", p, t.col(code), l, t.col(cOff))
	}
}

func (t *textOut) heading(title string, count int, code string) {
	h := title
	if count >= 0 {
		h = fmt.Sprintf("%s (%d)", title, count)
	}
	fmt.Fprintf(&t.b, "\n %s%s%s%s\n %s\n", t.col(code), t.col(cBold), h, t.col(cOff), strings.Repeat("-", min(t.width-2, 62)))
}

func statusCode(s string) string {
	switch s {
	case "FAIL":
		return cFail
	case "WARN":
		return cWarn
	case "PASS":
		return cPass
	case "INFO":
		return cInfo
	}
	return cUnk
}

// card writes one problem with its explanation and fix steps.
func (t *textOut) card(n int, f Finding) {
	code := statusCode(f.Status)
	head := fmt.Sprintf(" %s %d. ", marker[f.Status], n)
	t.para(head, strings.Repeat(" ", len(head)), f.Title, code+t.col(cBold))
	pad := "     "
	label := func(name, text string) {
		if text != "" {
			t.para(pad+name, pad+strings.Repeat(" ", len(name)), text, "")
		}
	}
	label("Problem: ", f.Problem)
	label("Why it matters: ", f.Why)
	if len(f.Steps) > 0 {
		fmt.Fprintf(&t.b, "%sHow to fix:\n", pad)
		for i, s := range f.Steps {
			p := fmt.Sprintf("%s  %c) ", pad, 'a'+i)
			t.para(p, strings.Repeat(" ", len(p)), s, "")
		}
	}
	label("More help: ", f.MoreHelp)
	label("Details: ", f.Detail)
	t.b.WriteString("\n")
}

func renderText(a *Audit, color bool, width int) string {
	t := &textOut{color: color, width: width}
	cs := cards(a)
	fails, warns, unks := byStatus(cs, "FAIL"), byStatus(cs, "WARN"), byStatus(cs, "UNKNOWN")
	passes, infos := byStatus(cs, "PASS"), byStatus(cs, "INFO")

	bar := strings.Repeat("=", min(width, 64))
	fmt.Fprintf(&t.b, "%s\n", bar)
	t.para(" ", "   ", fmt.Sprintf("TAILSCALE SECURITY CHECK  -  %s  -  %s", a.Host, a.Now.Format("2 Jan 2006 15:04")), cBold)

	var res []string
	if len(fails) > 0 {
		res = append(res, t.col(cFail)+plural(len(fails), "problem", "problems")+" to fix now"+t.col(cOff))
	}
	if len(warns) > 0 {
		res = append(res, t.col(cWarn)+fmt.Sprintf("%d to review", len(warns))+t.col(cOff))
	}
	if len(unks) > 0 {
		res = append(res, t.col(cUnk)+fmt.Sprintf("%d could not be checked", len(unks))+t.col(cOff))
	}
	res = append(res, t.col(cPass)+fmt.Sprintf("%d OK", len(passes))+t.col(cOff))
	if len(fails)+len(warns) == 0 {
		res = append([]string{t.col(cPass) + "No problems found" + t.col(cOff)}, res...)
	}
	fmt.Fprintf(&t.b, " RESULT: %s%s%s\n", t.col(cBold), strings.Join(res, "  |  "), t.col(cOff))
	admin := "no (some places were skipped)"
	if a.Elevated {
		admin = "yes"
	}
	pol := "not checked (add --policy FILE to check your access rules)"
	if a.PolicyFile != "" {
		pol = a.PolicyFile
	}
	t.para(" Admin rights: ", "               ", admin, "")
	t.para(" Policy file:  ", "               ", pol, "")
	fmt.Fprintf(&t.b, "%s\n", bar)
	t.para(" ", " ", "How to read this: [X] = a real problem, fix it soon. [!] = a risk worth fixing. [?] = could not be checked. [OK] = fine. [i] = for your information.", "")

	n := 0
	if len(fails) > 0 {
		t.heading("FIX NOW", len(fails), cFail)
		for _, f := range fails {
			n++
			t.card(n, f)
		}
	}
	if len(warns) > 0 {
		t.heading("REVIEW", len(warns), cWarn)
		for _, f := range warns {
			n++
			t.card(n, f)
		}
	}
	if len(unks) > 0 {
		t.heading("COULD NOT CHECK", len(unks), cUnk)
		for _, f := range unks {
			n++
			t.card(n, f)
		}
	}
	if len(passes) > 0 {
		t.heading("ALL GOOD", len(passes), cPass)
		for _, f := range passes {
			t.para(" "+t.col(cPass)+"[OK]"+t.col(cOff)+" ", "      ", f.Title, "")
		}
	}
	if len(infos) > 0 {
		t.heading("FOR YOUR INFORMATION", -1, cInfo)
		for _, f := range infos {
			t.para(" "+t.col(cInfo)+"[i]"+t.col(cOff)+"  ", "      ", f.Title, "")
			if f.Problem != "" {
				t.para("      ", "      ", f.Problem, "")
			}
		}
	}
	if a.Policy != nil && len(a.Policy.SSHRules) > 0 {
		t.heading("YOUR SSH RULES, IN PLAIN WORDS", -1, cBold)
		for _, r := range a.Policy.SSHRules {
			t.para(" - ", "   ", r.Summary, "")
		}
	}
	t.heading("NEXT STEPS", -1, cBold)
	if len(a.Todo) == 0 {
		t.para(" ", " ", "Nothing to do. Keep Tailscale updated and run this check again after you change your settings.", "")
	}
	for i, s := range a.Todo {
		p := fmt.Sprintf(" %d. ", i+1)
		t.para(p, strings.Repeat(" ", len(p)), s+".", "")
	}
	return t.b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func renderJSON(a *Audit) ([]byte, error) {
	rep := struct {
		Tool     string         `json:"tool"`
		Version  string         `json:"version"`
		Host     string         `json:"host"`
		Date     string         `json:"date"`
		OS       string         `json:"os"`
		Elevated bool           `json:"elevated"`
		Summary  map[string]int `json:"summary"`
		Findings []Finding      `json:"findings"`
		Policy   *PolicyResult  `json:"policy"`
		Todo     []string       `json:"todo"`
	}{"tailguard tailscale-audit (Go)", toolVersion, a.Host, a.Now.Format("2006-01-02 15:04:05 MST"), osName(),
		a.Elevated, counts(a), a.Local, a.Policy, nonNil(a.Todo)}
	b, err := json.MarshalIndent(rep, "", "  ")
	return append(b, '\n'), err
}
