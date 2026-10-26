package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var keyRe = regexp.MustCompile(`tskey-[A-Za-z0-9_-]{8,}`)

const (
	maxFileSize = 2 << 20 // skip files over 2 MB
	rootBudget  = 60 * time.Second
)

var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".cache": true, ".npm": true, ".nuget": true,
	"WinSxS": true, "INetCache": true, "WindowsApps": true, "Temp": true,
}

type scanRoot struct {
	path  string
	depth int // -1 = unlimited
}

func mask(k string) string {
	if len(k) > 10 {
		k = k[:10]
	}
	return k + "****(masked)"
}

func scanRoots() []scanRoot {
	if env := os.Getenv("TAILGUARD_SCAN_ROOTS"); env != "" {
		var r []scanRoot
		for _, p := range filepath.SplitList(env) {
			r = append(r, scanRoot{p, -1})
		}
		return r
	}
	if runtime.GOOS == "windows" {
		home, _ := os.UserHomeDir()
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		win := os.Getenv("SystemRoot")
		if win == "" {
			win = `C:\Windows`
		}
		// Small, high-value places first so a slow ProgramData can't starve them.
		return []scanRoot{
			{filepath.Join(win, `System32\Tasks`), -1},
			{filepath.Join(home, `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`), 1},
			{home, 5},
			{pd, 6},
		}
	}
	r := []scanRoot{{"/etc", -1}, {"/lib/systemd/system", -1}, {"/usr/lib/systemd/system", -1},
		{"/var/spool/cron", -1}, {"/root", 6}, {"/usr/local/bin", 2}, {"/usr/local/sbin", 2}, {"/opt/scripts", 3}}
	for _, g := range []string{"/home/*/.bash_history", "/home/*/.zsh_history", "/home/*/.ash_history",
		"/home/*/.profile", "/home/*/.bashrc", "/home/*/*.sh", "/home/*/bin"} {
		m, _ := filepath.Glob(g)
		for _, p := range m {
			r = append(r, scanRoot{p, 2})
		}
	}
	return r
}

// scanAuthKeys searches for stored auth keys and returns masked hits
// ("file: tskey-auth****(masked)"), paths skipped for lack of rights, and
// the folders whose scan hit the time limit (so a clean result is incomplete).
func scanAuthKeys(elevated bool, prog *Progress) (hits, skipped, incomplete []string) {
	seen := map[string]bool{}
	denied := map[string]bool{}
	files := 0

	for _, root := range scanRoots() {
		deadline := time.Now().Add(rootBudget)
		timedOut := false
		info, err := os.Stat(root.path)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				denied[root.path] = true
			}
			continue
		}
		base := strings.Count(filepath.Clean(root.path), string(os.PathSeparator))
		walk := func(p string, d fs.DirEntry, err error) error {
			if time.Now().After(deadline) {
				timedOut = true
				return filepath.SkipAll
			}
			if err != nil {
				if errors.Is(err, fs.ErrPermission) {
					denied[p] = true
				}
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p != root.path && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				if root.depth >= 0 && strings.Count(filepath.Clean(p), string(os.PathSeparator))-base >= root.depth {
					return filepath.SkipDir
				}
				prog.Scan(p, files)
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Size() > maxFileSize || fi.Size() == 0 {
				return nil
			}
			files++
			data, err := os.ReadFile(p)
			if err != nil {
				if errors.Is(err, fs.ErrPermission) {
					denied[p] = true
				}
				return nil
			}
			head := data
			if len(head) > 512 {
				head = head[:512]
			}
			// Windows task XML is UTF-16; drop NULs instead of skipping it.
			if bytes.HasPrefix(data, []byte{0xff, 0xfe}) {
				data = bytes.ReplaceAll(data, []byte{0}, nil)
			} else if bytes.IndexByte(head, 0) >= 0 {
				return nil
			}
			for _, k := range keyRe.FindAll(data, -1) {
				h := p + ": " + mask(string(k))
				if !seen[h] {
					seen[h] = true
					hits = append(hits, h)
				}
			}
			return nil
		}
		if info.IsDir() {
			_ = filepath.WalkDir(root.path, walk)
		} else {
			_ = walk(root.path, fs.FileInfoToDirEntry(info), nil)
		}
		if timedOut {
			incomplete = append(incomplete, root.path)
		}
	}
	sort.Strings(hits)

	if len(denied) > 0 {
		var d []string
		for p := range denied {
			d = append(d, p)
		}
		sort.Strings(d)
		more := ""
		if len(d) > 5 {
			more = " and " + strconv.Itoa(len(d)-5) + " more"
			d = d[:5]
		}
		skipped = append(skipped, "unreadable: "+strings.Join(d, ", ")+more)
	} else if !elevated && os.Getenv("TAILGUARD_SCAN_ROOTS") == "" && runtime.GOOS != "windows" {
		skipped = append(skipped, "unreadable files under /etc /root /var/spool/cron (not root)")
	}
	if len(incomplete) > 0 {
		skipped = append(skipped, "auth-key scan hit the "+rootBudget.String()+" limit in "+strings.Join(incomplete, ", "))
	}
	return hits, skipped, incomplete
}
