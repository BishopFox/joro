//go:build unix

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// isForeground reports whether this process is in the foreground process
// group of its controlling terminal. When false (e.g. `./joro &` left stdin
// attached to the tty), reading stdin would deliver SIGTTIN and stop the
// process. The update prompt uses this to skip the read entirely in that
// case and fall through with a non-destructive default.
func isForeground() bool {
	fgPgid, err := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	if err != nil {
		return false
	}
	return fgPgid == syscall.Getpgrp()
}
