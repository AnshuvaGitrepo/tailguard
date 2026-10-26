package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// plainName turns a policy selector into words.
func plainName(s string, dst bool) string {
	switch {
	case s == "*":
		if dst {
			return "any device"
		}
		return "anyone"
	case s == "autogroup:member":
		return "every user in your network"
	case s == "autogroup:self":
		return "their own devices"
	case s == "autogroup:tagged":
		return "every tagged device"
	case s == "autogroup:admin":
		return "admins"
	case strings.HasPrefix(s, "group:"):
		return "everyone in group '" + strings.TrimPrefix(s, "group:") + "'"
	case strings.HasPrefix(s, "tag:"):
		return "every device tagged '" + strings.TrimPrefix(s, "tag:") + "'"
	}
	return s
}

func plainList(list []string, dst bool) string {
	if len(list) == 0 {
		return "nobody"
	}
	var out []string
	for _, s := range list {
		out = append(out, plainName(s, dst))
	}
	if len(out) == 1 {
		return out[0]
	}
	return strings.Join(out[:len(out)-1], ", ") + " and " + out[len(out)-1]
}

func plainUsers(users []string) string {
	var out []string
	for _, u := range users {
		switch u {
		case "root":
			out = append(out, "root (full admin)")
		case "autogroup:nonroot":
			out = append(out, "any normal account")
		case "*":
			out = append(out, "any account")
		default:
			out = append(out, "'"+u+"'")
		}
	}
	if len(out) == 0 {
		return "no account"
	}
	if len(out) == 1 {
		return out[0]
	}
	return strings.Join(out[:len(out)-1], ", ") + " or " + out[len(out)-1]
}

func plainAction(a string) string {
	switch a {
	case "check":
		return "after confirming their login (check mode)"
	case "accept":
		return "with no extra check (accept mode)"
	}
	return "with action '" + a + "'"
}

// describeRule writes one SSH rule as a sentence.
func describeRule(r SSHRule) string {
	return fmt.Sprintf("SSH rule %d: %s can log in to %s as %s, %s.", r.Index,
		plainList(r.Src, false), plainList(r.Dst, true), plainUsers(r.Users), plainAction(r.Action))
}

func auditPolicy(data []byte) (*PolicyResult, error) {
	var pol map[string]any
	if err := json.Unmarshal(stripHuJSON(data), &pol); err != nil {
		return nil, err
	}
	r := &PolicyResult{SSHRules: []SSHRule{}, Findings: []Finding{}}
	add := func(f Finding) { r.Findings = append(r.Findings, withFix(f)) }

	rules := objList(pol["ssh"])
	if len(rules) == 0 {
		add(Finding{ID: "P-SSH", Status: "INFO", Check: "SSH rules", Title: "Your policy has no SSH rules, so Tailworm has nothing to use",
			Detail: `no rules in the "ssh" section`})
	}
	for i, rule := range rules {
		n := i + 1
		src, dst, users := strList(rule["src"]), strList(rule["dst"]), strList(rule["users"])
		action, ok := rule["action"].(string)
		if !ok {
			action = "(none)"
		}
		sr := SSHRule{n, nonNil(src), nonNil(dst), nonNil(users), action, ""}
		sr.Summary = describeRule(sr)
		r.SSHRules = append(r.SSHRules, sr)
		sTxt, dTxt, uTxt := strings.Join(src, ", "), strings.Join(dst, ", "), strings.Join(users, ", ")

		var broad []string
		for _, x := range src {
			if isBroad(x) {
				broad = append(broad, "src:"+x)
			}
		}
		for _, x := range dst {
			if isBroad(x) {
				broad = append(broad, "dst:"+x)
			}
		}
		if len(src) > 1 {
			broad = append(broad, fmt.Sprintf("%d-sources", len(src)))
		}
		if len(dst) > 1 {
			broad = append(broad, fmt.Sprintf("%d-destinations", len(dst)))
		}
		if len(broad) > 0 {
			problem := fmt.Sprintf("It lets %s log in to %s.", plainList(src, false), plainList(dst, true))
			if len(dst) == 1 && dst[0] == "autogroup:self" {
				problem += " Each person can only reach devices they own, so this is Tailscale's default and lower risk than most broad rules, but it is still more than one person-to-device pair."
			}
			add(Finding{ID: fmt.Sprintf("P-SSH-%d-BROAD", n), Status: "FAIL", Check: fmt.Sprintf("ssh rule #%d is broad", n),
				Title: fmt.Sprintf("SSH rule %d is too broad", n), Next: fmt.Sprintf("Delete or narrow SSH rule %d", n),
				Detail:  fmt.Sprintf("src=[%s] dst=[%s]; broad: %s", sTxt, dTxt, strings.Join(broad, " ")),
				Problem: problem,
				Why:     "If any one of those devices is hacked, the attacker can use this rule to get into the others. This is how Tailworm spreads.",
				Steps: []string{"If you don't use Tailscale SSH (see the 'devices accept Tailscale SSH' line in this report), delete this rule from the \"ssh\" section of your policy.",
					"If you do use it, replace it with one rule for each person and the one device they need, for example: {\"action\": \"check\", \"src\": [\"you@example.com\"], \"dst\": [\"tag:my-server\"], \"users\": [\"autogroup:nonroot\"]}",
					"Note: this check also flags any tag: or group: in a rule, because one tag or group can cover many devices or people."}})
		}
		if contains(users, "root") {
			add(Finding{ID: fmt.Sprintf("P-SSH-%d-ROOT", n), Status: "WARN", Check: fmt.Sprintf("ssh rule #%d allows root", n),
				Title: fmt.Sprintf("SSH rule %d allows logging in as root", n), Next: fmt.Sprintf("Remove root from SSH rule %d", n),
				Detail:  "users=[" + uTxt + "]",
				Problem: "The rule's \"users\" list includes \"root\", the all-powerful admin account.",
				Why:     "Anyone who gets in through this rule has full control of the device straight away.",
				Steps: []string{"Remove \"root\" from the \"users\" list (keep \"autogroup:nonroot\").",
					"Log in as a normal user and use sudo when you need admin rights."}})
		}
		if action == "accept" {
			add(Finding{ID: fmt.Sprintf("P-SSH-%d-ACCEPT", n), Status: "WARN", Check: fmt.Sprintf("ssh rule #%d uses accept", n),
				Title: fmt.Sprintf("SSH rule %d doesn't ask users to confirm their login", n), Next: fmt.Sprintf("Change SSH rule %d to check mode", n),
				Detail:  "action=accept",
				Problem: "The rule uses \"action\": \"accept\", so SSH connects without any extra check.",
				Why:     "A hacked device can use this rule straight away, without anyone noticing.",
				Steps: []string{"Change \"action\": \"accept\" to \"action\": \"check\".",
					"Optionally add \"checkPeriod\": \"1h\" so the confirmation is asked again every hour."}})
		}
		add(Finding{ID: fmt.Sprintf("P-SSH-%d-FWD", n), Status: "WARN", Check: fmt.Sprintf("ssh rule #%d cannot disable port forwarding", n),
			Title: "SSH port forwarding can't be blocked from your policy", Next: "Keep SSH rules narrow; on important servers use OpenSSH with forwarding turned off",
			Group:   "fwd",
			Ref:     fmt.Sprintf("SSH rule %d", n),
			Detail:  fwdNote,
			Problem: "Tailscale's policy file has no setting to block SSH port forwarding (checked in Tailscale's documentation on 26 Oct 2026).",
			Why:     "So anyone these SSH rules let in can tunnel to hidden services on the device. Tailworm uses this to become root.",
			Steps: []string{"Treat every SSH rule as if it gives full admin access, and keep each one as narrow as possible.",
				"For important servers, turn off Tailscale SSH on them (" + sudo + "tailscale set --ssh=false) and use normal OpenSSH with 'AllowTcpForwarding no' and 'AllowStreamLocalForwarding no' in sshd_config."}})
	}

	for _, sect := range []string{"nodeAttrs", "grants"} {
		for i, e := range objList(pol[sect]) {
			if e != nil && hasKey(e, "tailscale.com/app-connectors") {
				add(Finding{ID: fmt.Sprintf("P-APPC-%s-%d", sect, i+1), Status: "WARN", Check: fmt.Sprintf("app connector grant in %s #%d", sect, i+1),
					Title: fmt.Sprintf("Your policy turns on app connectors (\"%s\" entry %d)", sect, i+1), Next: "Remove the app connector entry from your policy if you don't use it",
					Detail:  fmt.Sprintf("%s #%d has tailscale.com/app-connectors", sect, i+1),
					Problem: "This entry gives devices the app connector feature (tailscale.com/app-connectors).",
					Why:     "The Tailworm report says app connectors can be used to get around your access rules.",
					Steps: []string{"If you don't use app connectors, delete this entry.",
						"If you do, limit it to the one or two devices that really need it."}})
			}
		}
	}

	ownDevices := "Replace it with rules for what you actually use. A safe start is letting each person reach only their own devices: "
	lockout := "Add a \"tests\" section and use Preview before saving, so you don't lock yourself out of a device."
	for i, acl := range objList(pol["acls"]) {
		if acl != nil && contains(strList(acl["src"]), "*") && contains(strList(acl["dst"]), "*:*") {
			add(Finding{ID: fmt.Sprintf("P-ACL-%d-ALLOWALL", i+1), Status: "WARN", Check: fmt.Sprintf("acl #%d allows everything", i+1),
				Title: fmt.Sprintf("Access rule %d lets every device reach every port on every other device", i+1), Next: "Replace the allow-everything access rule with specific rules",
				Detail:  "acls: src * -> dst *:*",
				Problem: "This \"acls\" entry is the 'allow everything' rule (\"*\" to \"*:*\").",
				Why:     "One hacked device can then reach every service on every other device in your network.",
				Steps: []string{ownDevices + "{\"action\": \"accept\", \"src\": [\"autogroup:member\"], \"dst\": [\"autogroup:self:*\"]}",
					"Then add one rule for each shared server and the ports people need on it.", lockout}})
		}
	}
	for i, g := range objList(pol["grants"]) {
		if g != nil && contains(strList(g["src"]), "*") && contains(strList(g["dst"]), "*") && contains(strList(g["ip"]), "*") {
			add(Finding{ID: fmt.Sprintf("P-GRANT-%d-ALLOWALL", i+1), Status: "WARN", Check: fmt.Sprintf("grant #%d allows everything", i+1),
				Title: fmt.Sprintf("Grant %d lets every device reach every port on every other device", i+1), Next: "Replace the allow-everything grant with specific grants",
				Detail:  "grants: src * -> dst * ip *",
				Problem: "This \"grants\" entry is the 'allow everything' rule (\"*\" to \"*\" on all ports). It is Tailscale's default.",
				Why:     "One hacked device can then reach every service on every other device in your network.",
				Steps: []string{ownDevices + "{\"src\": [\"autogroup:member\"], \"dst\": [\"autogroup:self\"], \"ip\": [\"*\"]}",
					"Then add one grant for each shared server and the ports people need on it.", lockout}})
		}
	}
	return r, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
