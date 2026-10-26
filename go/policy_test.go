package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestStripHuJSON(t *testing.T) {
	in := `{ // c
	"a": "http://x//y", /* block */
	"b": [1, 2,],
}`
	var m map[string]any
	if err := json.Unmarshal(stripHuJSON([]byte(in)), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["a"] != "http://x//y" {
		t.Errorf("string with // was changed: %v", m["a"])
	}
}

// TestPolicies checks the sample policies against tests/expected.txt.
func TestPolicies(t *testing.T) {
	exp, err := os.ReadFile(filepath.Join("..", "tests", "expected.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bad", "mixed", "good"} {
		data, err := os.ReadFile(filepath.Join("..", "tests", "policies", name+".hujson"))
		if err != nil {
			t.Fatal(err)
		}
		r, err := auditPolicy(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got, want []string
		for _, f := range r.Findings {
			got = append(got, f.ID+" "+f.Status)
		}
		for _, line := range strings.Split(strings.ReplaceAll(string(exp), "\r", ""), "\n") {
			if rest, ok := strings.CutPrefix(line, "policy-"+name+" "); ok {
				want = append(want, rest)
			}
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s:\n got  %v\n want %v", name, got, want)
		}
	}
}
