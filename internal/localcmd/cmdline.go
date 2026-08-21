package localcmd

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// Command lines for the targets Windows runs through cmd.exe.
//
// # The problem
//
// Windows processes receive the command line as one string and parse it themselves. Go
// builds that string with the CommandLineToArgvW rules, which is right for the vast
// majority of programs — and wrong for cmd.exe, which is what Windows uses to run a .bat
// or .cmd file. Go's own documentation names the exception:
//
//	Notable exceptions are msiexec.exe and cmd.exe (and thus, all batch files), which
//	have a different unquoting algorithm.
//
// Concretely, syscall's escaping handles quotes, backslashes and whitespace and leaves
// cmd.exe's own metacharacters — & | < > ( ) ^ — untouched. That matters here more than in
// most programs, because an argument may hold a captured URL, and a captured URL is chosen
// by whoever the operator's browser was talking to. A path or query containing "&" would
// stop being part of the argument and start being the next command.
//
// It also matters that a bare program name can land on a batch file without anyone asking
// for one: exec.LookPath honours PATHEXT, whose default list includes .bat and .cmd, so
// naming a tool by its plain name is enough.
//
// # The fix, and why it is sufficient
//
// Every token is wrapped in double quotes and every double quote inside it is doubled —
// cmd.exe's own escape, deliberately *not* the backslash-doubling rule Go applies, because
// cmd.exe does not implement that and applying it anyway is what produced this entire class
// of bug across every language that hit it.
//
// That is enough, and the reason is a counting argument rather than a list of characters
// someone remembered to handle. Doubling is what makes it work: a token containing k quotes
// emits 2k+2 of them, so for any *other* character the number of quotes before it within
// its token is 1 + 2*(quotes before it) — always odd. An odd count means cmd.exe is inside
// a quoted region, and inside quotes it treats & | < > ( ) ^ as ordinary text. So every
// character of every argument is quoted, for all inputs, and the command-separator class is
// closed rather than filtered. The only characters Joro leaves outside quotes are the single
// spaces it puts between tokens, which is exactly the argument separator cmd.exe should see.
//
// # What is refused, and what is merely reported
//
// A carriage return or newline is refused. cmd.exe has no escape for a line break inside a
// command line, so there is no correct output to produce, and mangling one would be worse
// than declining.
//
// Two expansions survive quoting and cannot be prevented from here. %NAME% is expanded by
// cmd.exe inside quotes as well as outside, and the batch-file escape %% only works inside
// a script rather than on a command line; !NAME! is the same when a script has enabled
// delayed expansion. Both read an environment variable into the argument. Neither runs
// anything, and the environment a command gets is a whitelist to begin with (see buildEnv),
// so they are documented rather than refused.
//
// # Where the guarantee ends
//
// SysProcAttr.CmdLine replaces the command line text only: the executable is passed to
// CreateProcess separately, from Spec.Path, which Joro resolved and stored. So nothing here
// can change *which* program runs, and what this buys is that cmd.exe executes nothing Joro
// did not name.
//
// It cannot buy more than that. A batch file that expands %1 into another command without
// quoting it re-opens the injection one layer further in, inside the script, where Joro has
// no say. That is the operator's script and their call, and the editor says so rather than
// implying a guarantee that stops at this file.

// cmdParsedExts are the extensions Windows executes by way of cmd.exe.
var cmdParsedExts = []string{".bat", ".cmd"}

// needsCmdEscaping reports whether a resolved target is parsed by cmd.exe rather than by
// the ordinary CommandLineToArgvW rules.
//
// Checked on every platform, not only Windows, so the rule cannot be platform-conditional
// and wrong: the same answer is used by Validate at install time, where the operator may
// well be on a different machine from the one that eventually runs it.
//
// cmd.exe itself is included because an operator may name it directly, and it has the same
// parsing whether it arrived as a shell or as a target. msiexec.exe — the other exception
// Go names — is deliberately not here: its unquoting differs but it chains no commands, so
// there is no separator class to close, and a speculative transformation would be more
// likely to break an argument than to protect one.
func needsCmdEscaping(path string) bool {
	base := strings.ToLower(baseName(path))
	if base == "cmd.exe" || base == "cmd" {
		return true
	}
	return slices.Contains(cmdParsedExts, strings.ToLower(filepath.Ext(base)))
}

// baseName is filepath.Base over both separators, whatever the host's own is.
//
// filepath.Base splits on the running platform's separator only, so on a Unix host it reads
// all of `C:\Windows\System32\cmd.exe` as the base name and the check above would miss it.
// That matters because Validate runs where the package is *installed*, which need not be
// where it is run — an automation exported from one machine and imported on another is an
// ordinary thing to do — so this classification has to give the same answer everywhere.
func baseName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// cmdCommandLine builds the whole command line for a cmd.exe-parsed target, program name
// first, as CreateProcess expects.
//
// The returned error means an argument cannot be represented at all; see the header.
func cmdCommandLine(path string, args []string) (string, error) {
	var b strings.Builder

	if err := cmdRepresentable(path); err != nil {
		return "", fmt.Errorf("command.path: %w", err)
	}
	b.WriteString(cmdQuote(path))

	for i, a := range args {
		if err := cmdRepresentable(a); err != nil {
			return "", fmt.Errorf("args[%d]: %w", i, err)
		}
		b.WriteByte(' ')
		b.WriteString(cmdQuote(a))
	}
	return b.String(), nil
}

// cmdRepresentable reports whether a token can be written into a cmd.exe command line at
// all.
func cmdRepresentable(s string) error {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return fmt.Errorf("contains a line break, which cmd.exe cannot be given inside a command "+
			"line and which this program is run through because its target is a batch file. Remove "+
			"the line break, or point the automation at an executable rather than a %s wrapper",
			strings.Join(cmdParsedExts, "/"))
	}
	if strings.ContainsRune(s, 0) {
		return fmt.Errorf("contains a NUL byte")
	}
	return nil
}

// cmdQuote wraps one token for cmd.exe: quoted, with every inner quote doubled. See the
// header for why that is sufficient.
//
// An empty token becomes `""`, which is how a program receives a deliberately empty
// argument rather than losing it.
func cmdQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			b.WriteString(`""`)
			continue
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}
