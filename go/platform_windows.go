//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

// isElevated: only an elevated process can open the raw disk device.
func isElevated() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// enableColor turns on ANSI escape handling in the Windows console.
// It returns false when stdout is not a console (redirected to a file).
func enableColor() bool {
	const enableVirtualTerminalProcessing = 0x0004
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if err := syscall.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	r, _, _ := kernel32.NewProc("SetConsoleMode").Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}

func stderrIsConsole() bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(os.Stderr.Fd()), &mode) == nil
}

// consoleWidth returns the visible width of the console window.
func consoleWidth() int {
	var info struct {
		size, cursor          [2]int16
		attr                  uint16
		left, top, right, bot int16
		max                   [2]int16
	}
	r, _, _ := kernel32.NewProc("GetConsoleScreenBufferInfo").Call(os.Stderr.Fd(), uintptr(unsafe.Pointer(&info)))
	if r == 0 || info.right <= info.left {
		return 80
	}
	return int(info.right-info.left) + 1
}
