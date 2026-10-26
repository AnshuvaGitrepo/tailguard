package main

import "strings"

// SSHRule is one entry of the policy "ssh" section, as listed in the report.
type SSHRule struct {
	Index   int      `json:"index"`
	Src     []string `json:"src"`
	Dst     []string `json:"dst"`
	Users   []string `json:"users"`
	Action  string   `json:"action"`
	Summary string   `json:"summary"`
}

// PolicyResult is the policy part of the report.
type PolicyResult struct {
	File     string    `json:"file"`
	SSHRules []SSHRule `json:"ssh_rules"`
	Findings []Finding `json:"findings"`
}

const fwdNote = "Tailscale's policy reference (kb/1337, kb/1193) documents no ssh-rule forwarding field. The node protocol carries per-rule flags (tailcfg.SSHAction allowLocalPortForwarding / allowRemotePortForwarding); reports say the hosted service can set them per rule, but that is undocumented. Host-level switch: TS_SSH_DISABLE_FORWARDING on tailscaled (in Tailscale's source, undocumented)."

// stripHuJSON removes // and /* */ comments outside strings and trailing
// commas before } or ], turning HuJSON into plain JSON.
func stripHuJSON(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inStr := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(in) {
				i++
				out = append(out, in[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			i-- // keep the newline
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
		case c == '}' || c == ']':
			j := len(out) - 1
			for j >= 0 && (out[j] == ' ' || out[j] == '\t' || out[j] == '\r' || out[j] == '\n') {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

func strList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func objList(v any) []map[string]any {
	list, _ := v.([]any)
	var out []map[string]any
	for _, x := range list {
		m, _ := x.(map[string]any)
		out = append(out, m) // keep nil to preserve numbering
	}
	return out
}

// isBroad reports selectors that always cover many people or devices.
func isBroad(s string) bool {
	return s == "*" || s == "autogroup:member" || s == "autogroup:tagged" || strings.HasPrefix(s, "group:")
}

// isTag reports a tag: selector. One tag is a single pair only if exactly one
// device carries it, which the policy file can't show, so it is a WARN.
func isTag(s string) bool { return strings.HasPrefix(s, "tag:") }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// hasKey reports whether any object key under v equals key.
func hasKey(v any, key string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if k == key || hasKey(val, key) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if hasKey(val, key) {
				return true
			}
		}
	}
	return false
}
