//go:build !unix && !windows

package localcmd

import (
	"os/exec"
	"syscall"
)

// The platforms that are neither Unix nor Windows — js/wasm, plan9. Joro is not built for
// them today; these exist so the package compiles rather than because the behaviour has
// been thought through, and that is the honest description of them.

// CapInlineInputBytes takes the most conservative of the figures the real platforms use,
// for the same reason everything else here is conservative: the behaviour has not been
// checked on these targets.
const CapInlineInputBytes = 24 << 10

func procAttr() *syscall.SysProcAttr { return nil }

// applyCmdLine has nothing to do: the cmd.exe parsing quirk is Windows-only.
func applyCmdLine(*exec.Cmd) error { return nil }

// killTree kills the command, and only the command. No process group, no tree walk.
func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
