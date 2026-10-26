package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Progress draws a one-line step bar on stderr while the audit runs, with a
// spinner, current folder, file count and elapsed time during the key scan.
// It is a no-op when stderr is not a console, and is erased before results print.
type Progress struct {
	on    bool
	total int
	start time.Time

	mu     sync.Mutex
	step   int
	label  string
	detail string
	files  int
	width  int // widest line drawn, so it can be blanked
	stop   chan struct{}
	done   chan struct{}
}

var spinner = []string{"|", "/", "-", `\`}

func newProgress(enabled bool, total int) *Progress {
	p := &Progress{on: enabled && stderrIsConsole(), total: total, start: time.Now()}
	if p.on {
		p.stop = make(chan struct{})
		p.done = make(chan struct{})
		go p.loop()
	}
	return p
}

// Step moves the bar to the next step.
func (p *Progress) Step(label string) {
	if !p.on {
		return
	}
	p.mu.Lock()
	p.step++
	p.label = label
	p.detail = ""
	p.files = 0
	p.mu.Unlock()
}

// Scan updates the folder and file count shown during the key scan.
func (p *Progress) Scan(folder string, files int) {
	if !p.on {
		return
	}
	p.mu.Lock()
	p.detail = folder
	p.files = files
	p.mu.Unlock()
}

// Done stops the spinner and erases the line.
func (p *Progress) Done() {
	if !p.on {
		return
	}
	close(p.stop)
	<-p.done
	p.mu.Lock()
	fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", p.width)+"\r")
	p.mu.Unlock()
}

func (p *Progress) loop() {
	defer close(p.done)
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for i := 0; ; i++ {
		p.draw(spinner[i%len(spinner)])
		select {
		case <-p.stop:
			return
		case <-t.C:
		}
	}
}

func (p *Progress) draw(spin string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	const barLen = 16
	filled := 0
	if p.total > 0 {
		filled = barLen * p.step / p.total
	}
	el := time.Since(p.start).Round(time.Second)
	line := fmt.Sprintf("[%s%s] %d/%d %s %s  %d:%02d", strings.Repeat("#", filled), strings.Repeat("-", barLen-filled),
		p.step, p.total, spin, p.label, int(el.Minutes()), int(el.Seconds())%60)
	if p.detail != "" {
		line += fmt.Sprintf("  | %d files  %s", p.files, p.detail)
	}
	// Keep to one console line so \r can redraw it.
	if max := consoleWidth() - 1; len(line) > max {
		line = line[:max-3] + "..."
	}
	pad := ""
	if len(line) < p.width {
		pad = strings.Repeat(" ", p.width-len(line))
	}
	if len(line) > p.width {
		p.width = len(line)
	}
	fmt.Fprint(os.Stderr, "\r"+line+pad)
}
