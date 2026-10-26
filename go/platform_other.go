//go:build !windows

package main

import (
	"os"
	"strconv"
)

func isElevated() bool { return os.Geteuid() == 0 }

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// enableColor reports whether stdout is a terminal.
func enableColor() bool { return isTerminal(os.Stdout) }

func stderrIsConsole() bool { return isTerminal(os.Stderr) }

// consoleWidth uses $COLUMNS when the shell exports it, else 80.
func consoleWidth() int {
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 20 {
		return n
	}
	return 80
}
