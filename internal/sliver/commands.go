package sliver

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CommandResult is returned by Dispatch for every command.
type CommandResult struct {
	Output     string `json:"output"`
	Error      string `json:"error,omitempty"`
	DownloadID string `json:"downloadId,omitempty"`
	Filename   string `json:"filename,omitempty"`
	// SessionChanged is set when `use` or `background` changes the active session.
	SessionChanged bool   `json:"sessionChanged,omitempty"`
	SessionID      string `json:"sessionId,omitempty"`
	SessionName    string `json:"sessionName,omitempty"`
	// Disconnected is set when `exit` disconnects.
	Disconnected bool `json:"disconnected,omitempty"`
}

// Dispatch parses a command string and routes it to the appropriate RPC.
func (c *Client) Dispatch(ctx context.Context, input string) CommandResult {
	args := shellSplit(input)
	if len(args) == 0 {
		return CommandResult{}
	}

	cmd := strings.ToLower(args[0])
	rest := args[1:]

	// Server-level commands (always available)
	switch cmd {
	case "help":
		return c.cmdHelp(rest)
	case "clear":
		return CommandResult{Output: "__clear__"}
	case "exit":
		c.Disconnect()
		return CommandResult{Output: "Disconnected from Sliver teamserver", Disconnected: true}
	case "sessions":
		return c.cmdSessions(ctx)
	case "beacons":
		return c.cmdBeacons(ctx)
	case "use":
		return c.cmdUse(ctx, rest)
	case "background":
		return c.cmdBackground()
	case "jobs":
		return c.cmdJobs(ctx, rest)
	case "mtls":
		return c.cmdMTLS(ctx, rest)
	case "http":
		return c.cmdHTTPListener(ctx, rest, false)
	case "https":
		return c.cmdHTTPListener(ctx, rest, true)
	case "dns":
		return c.cmdDNSListener(ctx, rest)
	case "wg":
		return c.cmdWGListener(ctx, rest)
	case "operators":
		return c.cmdOperators(ctx)
	case "version":
		return c.cmdVersion(ctx)
	case "implants":
		return c.cmdImplants(ctx)
	case "profiles":
		return c.cmdProfiles(ctx)
	case "hosts":
		return c.cmdHosts(ctx)
	case "loot":
		return c.cmdLoot(ctx)
	case "websites":
		return c.cmdWebsites(ctx)
	case "canaries":
		return c.cmdCanaries(ctx)
	case "builders":
		return c.cmdBuilders(ctx)
	case "tasks":
		return c.cmdTasks(ctx, rest)
	case "generate":
		return c.cmdGenerate(ctx, rest)

	// Stub commands
	case "settings":
		return CommandResult{Output: "Client settings are managed via the Joro Settings page"}
	case "aliases":
		return CommandResult{Output: "No aliases configured"}
	case "licenses":
		return CommandResult{Output: "Sliver is licensed under the GPLv3\nSee: https://github.com/BishopFox/sliver/blob/master/LICENSE"}
	case "update":
		return CommandResult{Output: "Updates are managed through the Sliver teamserver directly"}
	case "monitor", "wg-config", "wg-portfwd", "wg-socks", "cursed", "armory",
		"prelude-operator", "reaction", "stage-listener", "regenerate":
		return CommandResult{Output: fmt.Sprintf("Command '%s' is not yet implemented in this client", cmd)}
	}

	// Session-level commands (require active session)
	sessionID, _, isBeacon := c.GetActiveSession()
	if sessionID == "" {
		return CommandResult{Error: fmt.Sprintf("Unknown command '%s'. No active session - use 'use <id>' to interact with a session.", cmd)}
	}

	switch cmd {
	case "info":
		return c.cmdInfo(ctx, sessionID)
	case "ls":
		return c.cmdLs(ctx, sessionID, rest, isBeacon)
	case "cd":
		return c.cmdCd(ctx, sessionID, rest, isBeacon)
	case "pwd":
		return c.cmdPwd(ctx, sessionID, isBeacon)
	case "cat":
		return c.cmdCat(ctx, sessionID, rest, isBeacon)
	case "download":
		return c.cmdDownload(ctx, sessionID, rest, isBeacon)
	case "upload":
		return CommandResult{Error: "Use the upload button to select a file, or POST to /api/v1/sliver/upload"}
	case "mkdir":
		return c.cmdMkdir(ctx, sessionID, rest, isBeacon)
	case "rm":
		return c.cmdRm(ctx, sessionID, rest, isBeacon)
	case "ps":
		return c.cmdPs(ctx, sessionID, isBeacon)
	case "terminate":
		return c.cmdTerminate(ctx, sessionID, rest, isBeacon)
	case "procdump":
		return c.cmdProcdump(ctx, sessionID, rest, isBeacon)
	case "ifconfig":
		return c.cmdIfconfig(ctx, sessionID, isBeacon)
	case "netstat":
		return c.cmdNetstat(ctx, sessionID, rest, isBeacon)
	case "execute":
		return c.cmdExecute(ctx, sessionID, rest, isBeacon)
	case "shell":
		return CommandResult{Error: "Interactive shell is not yet supported. Use 'execute -o <cmd>' instead."}
	case "whoami":
		return c.cmdWhoami(ctx, sessionID, isBeacon)
	case "getuid":
		return c.cmdGetUID(ctx, sessionID, isBeacon)
	case "getgid":
		return c.cmdGetGID(ctx, sessionID, isBeacon)
	case "getprivs":
		return c.cmdGetPrivs(ctx, sessionID, isBeacon)
	case "screenshot":
		return c.cmdScreenshot(ctx, sessionID, isBeacon)
	case "env":
		return c.cmdEnv(ctx, sessionID, rest, isBeacon)
	case "execute-assembly":
		return CommandResult{Error: "execute-assembly requires a file upload. Use the upload endpoint with the assembly binary."}
	case "sideload":
		return CommandResult{Error: "sideload requires a file upload. Use the upload endpoint with the shared library."}
	case "kill":
		return c.cmdKill(ctx, sessionID, isBeacon)
	case "portfwd", "socks5", "pivots":
		return CommandResult{Output: fmt.Sprintf("Command '%s' is not yet implemented in this client", cmd)}
	default:
		return CommandResult{Error: fmt.Sprintf("Unknown command: %s. Type 'help' for available commands.", cmd)}
	}
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

func (c *Client) cmdHelp(args []string) CommandResult {
	sessionID, _, _ := c.GetActiveSession()

	if len(args) > 0 {
		return c.cmdHelpDetail(args[0])
	}

	var sb strings.Builder

	sb.WriteString("Commands:\n")
	sb.WriteString("=========\n")
	sb.WriteString("  clear       clear the screen\n")
	sb.WriteString("  exit        exit the shell\n")
	sb.WriteString("  help        use 'help [command]' for command help\n")
	sb.WriteString("\n")

	sb.WriteString("Generic:\n")
	sb.WriteString("========\n")
	sb.WriteString("  background      Background an active session\n")
	sb.WriteString("  beacons         Manage beacons\n")
	sb.WriteString("  builders        List external builders\n")
	sb.WriteString("  canaries        List previously generated canaries\n")
	sb.WriteString("  dns             Start a DNS listener\n")
	sb.WriteString("  generate        Generate an implant binary\n")
	sb.WriteString("  hosts           Manage the database of hosts\n")
	sb.WriteString("  http            Start an HTTP listener\n")
	sb.WriteString("  https           Start an HTTPS listener\n")
	sb.WriteString("  implants        List implant builds\n")
	sb.WriteString("  jobs            Job control\n")
	sb.WriteString("  loot            Manage the server's loot store\n")
	sb.WriteString("  mtls            Start an mTLS listener\n")
	sb.WriteString("  profiles        List existing profiles\n")
	sb.WriteString("  sessions        Session management\n")
	sb.WriteString("  tasks           Beacon task management\n")
	sb.WriteString("  use             Switch the active session or beacon\n")
	sb.WriteString("  version         Display version information\n")
	sb.WriteString("  websites        Host static content (used with HTTP C2)\n")
	sb.WriteString("  wg              Start a WireGuard listener\n")
	sb.WriteString("\n")

	sb.WriteString("Multiplayer:\n")
	sb.WriteString("============\n")
	sb.WriteString("  operators  Manage operators\n")

	if sessionID != "" {
		sb.WriteString("\n")
		sb.WriteString("Session Commands:\n")
		sb.WriteString("=================\n")
		sb.WriteString("  cat             Read file contents\n")
		sb.WriteString("  cd              Change directory\n")
		sb.WriteString("  download        Download a file\n")
		sb.WriteString("  env             List environment variables\n")
		sb.WriteString("  execute         Execute a command\n")
		sb.WriteString("  getgid          Get group ID\n")
		sb.WriteString("  getprivs        Get current privileges (Windows)\n")
		sb.WriteString("  getuid          Get user ID\n")
		sb.WriteString("  ifconfig        Get network interfaces\n")
		sb.WriteString("  info            Get session info\n")
		sb.WriteString("  kill            Kill the active session\n")
		sb.WriteString("  ls              List directory\n")
		sb.WriteString("  mkdir           Make directory\n")
		sb.WriteString("  netstat         Network connections\n")
		sb.WriteString("  procdump        Dump process memory\n")
		sb.WriteString("  ps              List processes\n")
		sb.WriteString("  pwd             Print working directory\n")
		sb.WriteString("  rm              Remove file or directory\n")
		sb.WriteString("  screenshot      Take a screenshot\n")
		sb.WriteString("  terminate       Terminate a process\n")
		sb.WriteString("  upload          Upload a file\n")
		sb.WriteString("  whoami          Get current user\n")
	}

	sb.WriteString("\nFor even more information, please see our wiki: https://github.com/BishopFox/sliver/wiki")

	return CommandResult{Output: sb.String()}
}

func (c *Client) cmdHelpDetail(cmd string) CommandResult {
	helpMap := map[string]string{
		"use":       "Usage: use [session/beacon id]\n\nSwitch the active session or beacon. Supports partial ID matching.",
		"sessions":  "Usage: sessions\n\nList all active sessions.",
		"beacons":   "Usage: beacons\n\nList all active beacons.",
		"jobs":      "Usage: jobs [-k id]\n\nList active jobs or kill a job with -k.",
		"mtls":      "Usage: mtls [--lhost host] [--lport port]\n\nStart an mTLS listener.",
		"http":      "Usage: http [--domain domain] [--lhost host] [--lport port]\n\nStart an HTTP listener.",
		"https":     "Usage: https [--domain domain] [--lhost host] [--lport port]\n\nStart an HTTPS listener.",
		"dns":       "Usage: dns [--domains domain1,domain2] [--lhost host] [--lport port]\n\nStart a DNS listener.",
		"wg":        "Usage: wg [--lhost host] [--lport port]\n\nStart a WireGuard listener.",
		"generate":  "Usage: generate [--os os] [--arch arch] [--format format] [--name name] [--beacon] --mtls host:port|--http url\n\nGenerate an implant binary.\n\nFormats: exe, shared, shellcode, service",
		"ls":        "Usage: ls [path]\n\nList directory contents.",
		"cd":        "Usage: cd <path>\n\nChange working directory.",
		"pwd":       "Usage: pwd\n\nPrint current working directory.",
		"cat":       "Usage: cat <path>\n\nRead and display file contents.",
		"download":  "Usage: download <path>\n\nDownload a file from the target.",
		"upload":    "Usage: upload <remote_path>\n\nUpload a file to the target. Use the file upload UI.",
		"mkdir":     "Usage: mkdir <path>\n\nCreate a directory.",
		"rm":        "Usage: rm [-r] [-f] <path>\n\nRemove a file or directory.",
		"ps":        "Usage: ps\n\nList running processes.",
		"terminate": "Usage: terminate <pid>\n\nTerminate a process by PID.",
		"procdump":  "Usage: procdump <pid>\n\nDump process memory.",
		"ifconfig":  "Usage: ifconfig\n\nGet network interface information.",
		"netstat":   "Usage: netstat [-T tcp] [-u udp] [-4 ipv4] [-6 ipv6] [-l listening]\n\nDisplay network connections.",
		"execute":   "Usage: execute [-o] <command> [args...]\n\nExecute a command. Use -o to capture output.",
		"whoami":    "Usage: whoami\n\nGet current user identity.",
		"getuid":    "Usage: getuid\n\nGet current user ID.",
		"getgid":    "Usage: getgid\n\nGet current group ID.",
		"getprivs":  "Usage: getprivs\n\nGet current privileges (Windows).",
		"screenshot": "Usage: screenshot\n\nTake a screenshot of the target's desktop.",
		"env":       "Usage: env [name]\n\nList environment variables. Optionally filter by name.",
		"kill":      "Usage: kill\n\nKill the active session.",
		"info":      "Usage: info\n\nDisplay detailed information about the active session.",
	}

	if help, ok := helpMap[strings.ToLower(cmd)]; ok {
		return CommandResult{Output: help}
	}
	return CommandResult{Error: fmt.Sprintf("No help available for '%s'", cmd)}
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

func (c *Client) cmdSessions(ctx context.Context) CommandResult {
	sessions, err := c.ListSessions(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(sessions) == 0 {
		return CommandResult{Output: "No active sessions"}
	}

	headers := []string{"ID", "Name", "Transport", "Remote Address", "Hostname", "Username", "OS", "Arch"}
	var rows [][]string
	for _, s := range sessions {
		rows = append(rows, []string{
			shortID(s.ID), s.Name, s.Transport, s.RemoteAddress,
			s.Hostname, s.Username, s.OS, s.Arch,
		})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdBeacons(ctx context.Context) CommandResult {
	beacons, err := c.ListBeacons(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(beacons) == 0 {
		return CommandResult{Output: "No active beacons"}
	}

	headers := []string{"ID", "Name", "Transport", "Remote Address", "Hostname", "Username", "OS", "Arch"}
	var rows [][]string
	for _, b := range beacons {
		rows = append(rows, []string{
			shortID(b.ID), b.Name, b.Transport, b.RemoteAddress,
			b.Hostname, b.Username, b.OS, b.Arch,
		})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdUse(ctx context.Context, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{Error: "Usage: use <session/beacon id>"}
	}

	target := args[0]

	// Try sessions first
	sessions, _ := c.ListSessions(ctx)
	for _, s := range sessions {
		if strings.HasPrefix(s.ID, target) || s.Name == target {
			c.SetActiveSession(s.ID, s.Name, false)
			return CommandResult{
				Output:         fmt.Sprintf("Active session %s (%s)", s.Name, shortID(s.ID)),
				SessionChanged: true,
				SessionID:      s.ID,
				SessionName:    s.Name,
			}
		}
	}

	// Try beacons
	beacons, _ := c.ListBeacons(ctx)
	for _, b := range beacons {
		if strings.HasPrefix(b.ID, target) || b.Name == target {
			c.SetActiveSession(b.ID, b.Name, true)
			return CommandResult{
				Output:         fmt.Sprintf("Active beacon %s (%s)", b.Name, shortID(b.ID)),
				SessionChanged: true,
				SessionID:      b.ID,
				SessionName:    b.Name,
			}
		}
	}

	return CommandResult{Error: fmt.Sprintf("No session or beacon found matching '%s'", target)}
}

func (c *Client) cmdBackground() CommandResult {
	c.ClearActiveSession()
	return CommandResult{
		Output:         "Background",
		SessionChanged: true,
		SessionID:      "",
		SessionName:    "",
	}
}

func (c *Client) cmdInfo(ctx context.Context, sessionID string) CommandResult {
	sessions, err := c.ListSessions(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}

	for _, s := range sessions {
		if s.ID == sessionID {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("        Session ID: %s\n", s.ID))
			sb.WriteString(fmt.Sprintf("              Name: %s\n", s.Name))
			sb.WriteString(fmt.Sprintf("          Hostname: %s\n", s.Hostname))
			sb.WriteString(fmt.Sprintf("          Username: %s\n", s.Username))
			sb.WriteString(fmt.Sprintf("                OS: %s\n", s.OS))
			sb.WriteString(fmt.Sprintf("              Arch: %s\n", s.Arch))
			sb.WriteString(fmt.Sprintf("         Transport: %s\n", s.Transport))
			sb.WriteString(fmt.Sprintf("    Remote Address: %s\n", s.RemoteAddress))
			sb.WriteString(fmt.Sprintf("           Version: %s\n", s.Version))
			return CommandResult{Output: sb.String()}
		}
	}

	// Try beacons
	beacons, _ := c.ListBeacons(ctx)
	for _, b := range beacons {
		if b.ID == sessionID {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("         Beacon ID: %s\n", b.ID))
			sb.WriteString(fmt.Sprintf("              Name: %s\n", b.Name))
			sb.WriteString(fmt.Sprintf("          Hostname: %s\n", b.Hostname))
			sb.WriteString(fmt.Sprintf("          Username: %s\n", b.Username))
			sb.WriteString(fmt.Sprintf("                OS: %s\n", b.OS))
			sb.WriteString(fmt.Sprintf("              Arch: %s\n", b.Arch))
			sb.WriteString(fmt.Sprintf("         Transport: %s\n", b.Transport))
			sb.WriteString(fmt.Sprintf("    Remote Address: %s\n", b.RemoteAddress))
			return CommandResult{Output: sb.String()}
		}
	}

	return CommandResult{Error: "Session not found"}
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

func (c *Client) cmdLs(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	result, err := c.Ls(ctx, sessionID, path, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}

	if !result.Exists {
		return CommandResult{Error: fmt.Sprintf("Path does not exist: %s", path)}
	}

	var sb strings.Builder
	sb.WriteString(result.Path + "\n")

	if len(result.Files) == 0 {
		sb.WriteString("  (empty)")
		return CommandResult{Output: sb.String()}
	}

	headers := []string{"Mode", "Size", "Modified", "Name"}
	var rows [][]string
	for _, f := range result.Files {
		name := f.Name
		if f.IsDir {
			name += "/"
		}
		if f.Link != "" {
			name += " -> " + f.Link
		}
		modStr := ""
		if f.ModTime > 0 {
			modStr = time.Unix(f.ModTime, 0).Format("2006-01-02 15:04")
		}
		rows = append(rows, []string{f.Mode, formatSize(f.Size), modStr, name})
	}

	sb.WriteString(formatTable(headers, rows))
	return CommandResult{Output: sb.String()}
}

func (c *Client) cmdCd(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	if len(args) == 0 {
		return CommandResult{Error: "Usage: cd <path>"}
	}

	newPath, err := c.Cd(ctx, sessionID, args[0], isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: newPath}
}

func (c *Client) cmdPwd(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	path, err := c.Pwd(ctx, sessionID, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: path}
}

func (c *Client) cmdCat(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	if len(args) == 0 {
		return CommandResult{Error: "Usage: cat <path>"}
	}

	data, _, err := c.Download(ctx, sessionID, args[0], isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: string(data)}
}

func (c *Client) cmdDownload(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	if len(args) == 0 {
		return CommandResult{Error: "Usage: download <path>"}
	}

	data, remotePath, err := c.Download(ctx, sessionID, args[0], isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}

	filename := filepath.Base(remotePath)
	dlID := c.StoreDownload(data, filename)
	return CommandResult{
		Output:     fmt.Sprintf("Downloaded %s (%s)", remotePath, formatSize(int64(len(data)))),
		DownloadID: dlID,
		Filename:   filename,
	}
}

func (c *Client) cmdMkdir(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	if len(args) == 0 {
		return CommandResult{Error: "Usage: mkdir <path>"}
	}

	path, err := c.Mkdir(ctx, sessionID, args[0], isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: fmt.Sprintf("Created %s", path)}
}

func (c *Client) cmdRm(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	recursive := false
	force := false
	var path string

	for _, a := range args {
		switch a {
		case "-r", "--recursive":
			recursive = true
		case "-f", "--force":
			force = true
		case "-rf", "-fr":
			recursive = true
			force = true
		default:
			if path == "" {
				path = a
			}
		}
	}

	if path == "" {
		return CommandResult{Error: "Usage: rm [-r] [-f] <path>"}
	}

	if err := c.Rm(ctx, sessionID, path, recursive, force, isBeacon); err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: fmt.Sprintf("Removed %s", path)}
}

// ---------------------------------------------------------------------------
// Process
// ---------------------------------------------------------------------------

func (c *Client) cmdPs(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	procs, err := c.Ps(ctx, sessionID, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(procs) == 0 {
		return CommandResult{Output: "No processes"}
	}

	headers := []string{"PID", "PPID", "Owner", "Arch", "Executable"}
	var rows [][]string
	for _, p := range procs {
		rows = append(rows, []string{
			strconv.Itoa(int(p.Pid)),
			strconv.Itoa(int(p.Ppid)),
			p.Owner,
			p.Arch,
			p.Executable,
		})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdTerminate(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	if len(args) == 0 {
		return CommandResult{Error: "Usage: terminate <pid>"}
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return CommandResult{Error: "Invalid PID"}
	}

	if err := c.Terminate(ctx, sessionID, int32(pid), isBeacon); err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: fmt.Sprintf("Terminated process %d", pid)}
}

func (c *Client) cmdProcdump(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	if len(args) == 0 {
		return CommandResult{Error: "Usage: procdump <pid>"}
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return CommandResult{Error: "Invalid PID"}
	}

	data, err := c.ProcessDump(ctx, sessionID, int32(pid), isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}

	filename := fmt.Sprintf("procdump_%d.bin", pid)
	dlID := c.StoreDownload(data, filename)
	return CommandResult{
		Output:     fmt.Sprintf("Process dump %d (%s)", pid, formatSize(int64(len(data)))),
		DownloadID: dlID,
		Filename:   filename,
	}
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

func (c *Client) cmdIfconfig(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	ifaces, err := c.Ifconfig(ctx, sessionID, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(ifaces) == 0 {
		return CommandResult{Output: "No network interfaces"}
	}

	var sb strings.Builder
	for _, iface := range ifaces {
		sb.WriteString(fmt.Sprintf("%s (index %d)\n", iface.Name, iface.Index))
		if iface.MAC != "" {
			sb.WriteString(fmt.Sprintf("  MAC: %s\n", iface.MAC))
		}
		if iface.MTU > 0 {
			sb.WriteString(fmt.Sprintf("  MTU: %d\n", iface.MTU))
		}
		for _, ip := range iface.IPAddresses {
			sb.WriteString(fmt.Sprintf("  IP: %s\n", ip))
		}
		sb.WriteString("\n")
	}
	return CommandResult{Output: strings.TrimRight(sb.String(), "\n")}
}

func (c *Client) cmdNetstat(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	tcp, udp, ip4, ip6, listening := true, false, true, false, false

	for _, a := range args {
		switch a {
		case "-T", "--tcp":
			tcp = true
		case "-u", "--udp":
			udp = true
		case "-4", "--ip4":
			ip4 = true
		case "-6", "--ip6":
			ip6 = true
		case "-l", "--listening":
			listening = true
		}
	}

	entries, err := c.Netstat(ctx, sessionID, tcp, udp, ip4, ip6, listening, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(entries) == 0 {
		return CommandResult{Output: "No connections"}
	}

	headers := []string{"Protocol", "Local Address", "Remote Address", "State", "PID/Program"}
	var rows [][]string
	for _, e := range entries {
		local := fmt.Sprintf("%s:%d", e.LocalAddr.IP, e.LocalAddr.Port)
		remote := fmt.Sprintf("%s:%d", e.RemoteAddr.IP, e.RemoteAddr.Port)
		proc := ""
		if e.Process.Pid > 0 {
			proc = fmt.Sprintf("%d/%s", e.Process.Pid, e.Process.Executable)
		}
		rows = append(rows, []string{e.Protocol, local, remote, e.SkState, proc})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

func (c *Client) cmdExecute(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	output := false
	var cmdArgs []string

	i := 0
	for i < len(args) {
		switch args[i] {
		case "-o", "--output":
			output = true
			i++
		default:
			cmdArgs = args[i:]
			i = len(args)
		}
	}

	if len(cmdArgs) == 0 {
		return CommandResult{Error: "Usage: execute [-o] <command> [args...]"}
	}

	if !output {
		// Still capture output by default in our UI context
		output = true
	}

	stdout, stderr, err := c.Execute(ctx, sessionID, cmdArgs[0], cmdArgs[1:], isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}

	var sb strings.Builder
	if stdout != "" {
		sb.WriteString(stdout)
	}
	if stderr != "" {
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("STDERR: " + stderr)
	}
	if sb.Len() == 0 {
		return CommandResult{Output: "[no output]"}
	}
	return CommandResult{Output: sb.String()}
}

// ---------------------------------------------------------------------------
// Recon
// ---------------------------------------------------------------------------

func (c *Client) cmdWhoami(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	owner, err := c.CurrentTokenOwner(ctx, sessionID, isBeacon)
	if err != nil {
		// Fallback to execute whoami
		stdout, _, execErr := c.Execute(ctx, sessionID, "whoami", nil, isBeacon)
		if execErr != nil {
			return CommandResult{Error: err.Error()}
		}
		return CommandResult{Output: strings.TrimSpace(stdout)}
	}
	return CommandResult{Output: owner}
}

func (c *Client) cmdGetUID(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	stdout, _, err := c.Execute(ctx, sessionID, "id", []string{"-u"}, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: fmt.Sprintf("UID: %s", strings.TrimSpace(stdout))}
}

func (c *Client) cmdGetGID(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	stdout, _, err := c.Execute(ctx, sessionID, "id", []string{"-g"}, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: fmt.Sprintf("GID: %s", strings.TrimSpace(stdout))}
}

func (c *Client) cmdGetPrivs(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	result, err := c.GetPrivs(ctx, sessionID, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}

	var sb strings.Builder
	if result.ProcessName != "" {
		sb.WriteString(fmt.Sprintf("Process: %s\n", result.ProcessName))
	}
	if result.ProcessIntegrity != "" {
		sb.WriteString(fmt.Sprintf("Integrity: %s\n", result.ProcessIntegrity))
	}

	if len(result.PrivInfo) > 0 {
		sb.WriteString("\n")
		headers := []string{"Name", "Description", "Enabled"}
		var rows [][]string
		for _, p := range result.PrivInfo {
			enabled := "No"
			if p.Enabled {
				enabled = "Yes"
			}
			rows = append(rows, []string{p.Name, p.Description, enabled})
		}
		sb.WriteString(formatTable(headers, rows))
	}

	return CommandResult{Output: sb.String()}
}

func (c *Client) cmdScreenshot(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	data, err := c.Screenshot(ctx, sessionID, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(data) == 0 {
		return CommandResult{Error: "Empty screenshot data"}
	}

	filename := fmt.Sprintf("screenshot_%s.png", time.Now().Format("20060102_150405"))
	dlID := c.StoreDownload(data, filename)
	return CommandResult{
		Output:     fmt.Sprintf("Screenshot saved (%s)", formatSize(int64(len(data)))),
		DownloadID: dlID,
		Filename:   filename,
	}
}

func (c *Client) cmdEnv(ctx context.Context, sessionID string, args []string, isBeacon bool) CommandResult {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	vars, err := c.GetEnv(ctx, sessionID, name, isBeacon)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(vars) == 0 {
		return CommandResult{Output: "No environment variables"}
	}

	var sb strings.Builder
	for _, v := range vars {
		sb.WriteString(fmt.Sprintf("%s=%s\n", v.Key, v.Value))
	}
	return CommandResult{Output: strings.TrimRight(sb.String(), "\n")}
}

func (c *Client) cmdKill(ctx context.Context, sessionID string, isBeacon bool) CommandResult {
	if err := c.Kill(ctx, sessionID, isBeacon); err != nil {
		return CommandResult{Error: err.Error()}
	}
	c.ClearActiveSession()
	return CommandResult{
		Output:         "Session killed",
		SessionChanged: true,
		SessionID:      "",
		SessionName:    "",
	}
}

// ---------------------------------------------------------------------------
// Server-level: Jobs & Listeners
// ---------------------------------------------------------------------------

func (c *Client) cmdJobs(ctx context.Context, args []string) CommandResult {
	// Check for kill flag
	for i, a := range args {
		if (a == "-k" || a == "--kill") && i+1 < len(args) {
			id, err := strconv.Atoi(args[i+1])
			if err != nil {
				return CommandResult{Error: "Invalid job ID"}
			}
			success, err := c.KillJob(ctx, uint32(id))
			if err != nil {
				return CommandResult{Error: err.Error()}
			}
			if success {
				return CommandResult{Output: fmt.Sprintf("Killed job %d", id)}
			}
			return CommandResult{Error: fmt.Sprintf("Failed to kill job %d", id)}
		}
	}

	jobs, err := c.GetJobs(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(jobs) == 0 {
		return CommandResult{Output: "No active jobs"}
	}

	headers := []string{"ID", "Name", "Protocol", "Port"}
	var rows [][]string
	for _, j := range jobs {
		rows = append(rows, []string{
			strconv.Itoa(int(j.ID)),
			j.Name,
			j.Protocol,
			strconv.Itoa(int(j.Port)),
		})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdMTLS(ctx context.Context, args []string) CommandResult {
	host := "0.0.0.0"
	port := uint32(8888)
	flags := parseFlags(args)

	if v, ok := flags["lhost"]; ok {
		host = v
	}
	if v, ok := flags["lport"]; ok {
		if p, err := strconv.Atoi(v); err == nil {
			port = uint32(p)
		}
	}

	jobID, err := c.StartMTLSListener(ctx, host, port)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: fmt.Sprintf("[*] mTLS listener started on %s:%d (job %d)", host, port, jobID)}
}

func (c *Client) cmdHTTPListener(ctx context.Context, args []string, secure bool) CommandResult {
	host := "0.0.0.0"
	port := uint32(80)
	if secure {
		port = 443
	}
	domain := ""
	flags := parseFlags(args)

	if v, ok := flags["lhost"]; ok {
		host = v
	}
	if v, ok := flags["lport"]; ok {
		if p, err := strconv.Atoi(v); err == nil {
			port = uint32(p)
		}
	}
	if v, ok := flags["domain"]; ok {
		domain = v
	}

	var jobID uint32
	var err error
	if secure {
		jobID, err = c.StartHTTPSListener(ctx, domain, host, port)
	} else {
		jobID, err = c.StartHTTPListener(ctx, domain, host, port)
	}
	if err != nil {
		return CommandResult{Error: err.Error()}
	}

	proto := "HTTP"
	if secure {
		proto = "HTTPS"
	}
	return CommandResult{Output: fmt.Sprintf("[*] %s listener started on %s:%d (job %d)", proto, host, port, jobID)}
}

func (c *Client) cmdDNSListener(ctx context.Context, args []string) CommandResult {
	host := "0.0.0.0"
	port := uint32(53)
	var domains []string
	flags := parseFlags(args)

	if v, ok := flags["lhost"]; ok {
		host = v
	}
	if v, ok := flags["lport"]; ok {
		if p, err := strconv.Atoi(v); err == nil {
			port = uint32(p)
		}
	}
	if v, ok := flags["domains"]; ok {
		domains = strings.Split(v, ",")
	}

	jobID, err := c.StartDNSListener(ctx, domains, host, port)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: fmt.Sprintf("[*] DNS listener started on %s:%d (job %d)", host, port, jobID)}
}

func (c *Client) cmdWGListener(ctx context.Context, args []string) CommandResult {
	host := "0.0.0.0"
	port := uint32(53)
	flags := parseFlags(args)

	if v, ok := flags["lhost"]; ok {
		host = v
	}
	if v, ok := flags["lport"]; ok {
		if p, err := strconv.Atoi(v); err == nil {
			port = uint32(p)
		}
	}

	jobID, err := c.StartWGListener(ctx, host, port)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: fmt.Sprintf("[*] WireGuard listener started on %s:%d (job %d)", host, port, jobID)}
}

// ---------------------------------------------------------------------------
// Server-level: Info & Management
// ---------------------------------------------------------------------------

func (c *Client) cmdOperators(ctx context.Context) CommandResult {
	ops, err := c.GetOperators(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(ops) == 0 {
		return CommandResult{Output: "No operators"}
	}

	headers := []string{"Name", "Status"}
	var rows [][]string
	for _, o := range ops {
		status := "Offline"
		if o.Online {
			status = "Online"
		}
		rows = append(rows, []string{o.Name, status})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdVersion(ctx context.Context) CommandResult {
	v, err := c.GetVersion(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Server v%d.%d.%d", v.Major, v.Minor, v.Patch))
	if v.Commit != "" {
		sb.WriteString(fmt.Sprintf(" - %s", shortID(v.Commit)))
	}
	if v.Dirty {
		sb.WriteString(" (dirty)")
	}
	if v.OS != "" || v.Arch != "" {
		sb.WriteString(fmt.Sprintf("\nCompiled for %s/%s", v.OS, v.Arch))
	}
	return CommandResult{Output: sb.String()}
}

func (c *Client) cmdImplants(ctx context.Context) CommandResult {
	builds, err := c.ImplantBuilds(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(builds) == 0 {
		return CommandResult{Output: "No implant builds"}
	}

	headers := []string{"Name", "OS", "Arch", "Format"}
	var rows [][]string
	for _, b := range builds {
		rows = append(rows, []string{b.Name, b.OS, b.Arch, b.Format})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdProfiles(ctx context.Context) CommandResult {
	profiles, err := c.ImplantProfiles(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(profiles) == 0 {
		return CommandResult{Output: "No implant profiles"}
	}

	headers := []string{"Name", "OS", "Arch"}
	var rows [][]string
	for _, p := range profiles {
		rows = append(rows, []string{p.Name, p.OS, p.Arch})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdHosts(ctx context.Context) CommandResult {
	hosts, err := c.Hosts(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(hosts) == 0 {
		return CommandResult{Output: "No hosts"}
	}

	headers := []string{"ID", "Hostname", "OS Version"}
	var rows [][]string
	for _, h := range hosts {
		rows = append(rows, []string{
			strconv.Itoa(int(h.ID)),
			h.Hostname,
			h.OSVersion,
		})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdLoot(ctx context.Context) CommandResult {
	loot, err := c.LootAll(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(loot) == 0 {
		return CommandResult{Output: "No loot"}
	}

	headers := []string{"ID", "Name", "Type"}
	var rows [][]string
	for _, l := range loot {
		typeName := "File"
		if l.Type == 1 {
			typeName = "Credential"
		}
		rows = append(rows, []string{shortID(l.ID), l.Name, typeName})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdWebsites(ctx context.Context) CommandResult {
	sites, err := c.Websites(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(sites) == 0 {
		return CommandResult{Output: "No websites"}
	}

	headers := []string{"Name"}
	var rows [][]string
	for _, s := range sites {
		rows = append(rows, []string{s.Name})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdCanaries(ctx context.Context) CommandResult {
	canaries, err := c.Canaries(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(canaries) == 0 {
		return CommandResult{Output: "No canaries"}
	}

	headers := []string{"Domain", "Implant", "Triggered"}
	var rows [][]string
	for _, cn := range canaries {
		triggered := "No"
		if cn.Triggered {
			triggered = "Yes"
		}
		rows = append(rows, []string{cn.Domain, cn.ImplantName, triggered})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdBuilders(ctx context.Context) CommandResult {
	builders, err := c.Builders(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(builders) == 0 {
		return CommandResult{Output: "No external builders"}
	}

	headers := []string{"Name", "Operator", "GOOS", "GOARCH"}
	var rows [][]string
	for _, b := range builders {
		rows = append(rows, []string{b.Name, b.Operator, b.GOOS, b.GOARCH})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdTasks(ctx context.Context, args []string) CommandResult {
	// Get active session (which should be a beacon for tasks)
	beaconID := ""
	if len(args) > 0 {
		beaconID = args[0]
	} else {
		beaconID, _, _ = c.GetActiveSession()
	}
	if beaconID == "" {
		return CommandResult{Error: "Usage: tasks [beacon_id] or select a beacon with 'use'"}
	}

	tasks, err := c.GetBeaconTasks(ctx, beaconID)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(tasks) == 0 {
		return CommandResult{Output: "No tasks"}
	}

	headers := []string{"ID", "State", "Description", "Created"}
	var rows [][]string
	for _, t := range tasks {
		created := ""
		if t.CreatedAt > 0 {
			created = time.Unix(t.CreatedAt, 0).Format("2006-01-02 15:04")
		}
		rows = append(rows, []string{shortID(t.ID), t.State, t.Description, created})
	}
	return CommandResult{Output: formatTable(headers, rows)}
}

func (c *Client) cmdGenerate(ctx context.Context, args []string) CommandResult {
	flags := parseFlags(args)
	config := ImplantGenerateConfig{
		GOOS:   "linux",
		GOARCH: "amd64",
		Format: 2, // EXECUTABLE
	}

	if v, ok := flags["os"]; ok {
		config.GOOS = v
	}
	if v, ok := flags["arch"]; ok {
		config.GOARCH = v
	}
	if v, ok := flags["name"]; ok {
		config.Name = v
	}
	if v, ok := flags["format"]; ok {
		switch strings.ToLower(v) {
		case "shared", "shared_lib":
			config.Format = 0
		case "shellcode":
			config.Format = 1
		case "exe", "executable":
			config.Format = 2
		case "service":
			config.Format = 3
		}
	}
	if _, ok := flags["beacon"]; ok {
		config.IsBeacon = true
	}

	// C2 config
	if v, ok := flags["mtls"]; ok {
		config.C2 = append(config.C2, ImplantC2Config{Priority: 0, URL: "mtls://" + v})
	}
	if v, ok := flags["http"]; ok {
		url := v
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		config.C2 = append(config.C2, ImplantC2Config{Priority: 0, URL: url})
	}
	if v, ok := flags["https"]; ok {
		url := v
		if !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}
		config.C2 = append(config.C2, ImplantC2Config{Priority: 0, URL: url})
	}
	if v, ok := flags["dns"]; ok {
		config.C2 = append(config.C2, ImplantC2Config{Priority: 0, URL: "dns://" + v})
	}

	if len(config.C2) == 0 {
		return CommandResult{Error: "At least one C2 endpoint is required. Use --mtls, --http, --https, or --dns flags."}
	}

	data, err := c.Generate(ctx, config)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(data) == 0 {
		return CommandResult{Error: "Empty implant binary returned"}
	}

	filename := config.Name
	if filename == "" {
		filename = "implant"
	}
	if config.GOOS == "windows" {
		filename += ".exe"
	}

	dlID := c.StoreDownload(data, filename)
	return CommandResult{
		Output:     fmt.Sprintf("[*] Implant generated: %s/%s %s (%s)", config.GOOS, config.GOARCH, filename, formatSize(int64(len(data)))),
		DownloadID: dlID,
		Filename:   filename,
	}
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

func formatTable(headers []string, rows [][]string) string {
	if len(headers) == 0 || len(rows) == 0 {
		return ""
	}

	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder

	// Header
	for i, h := range headers {
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(padRight(h, widths[i]))
	}
	sb.WriteString("\n")

	// Separator
	for i, w := range widths {
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(strings.Repeat("─", w))
	}
	sb.WriteString("\n")

	// Rows
	for _, row := range rows {
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				sb.WriteString("  ")
			}
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			sb.WriteString(padRight(cell, widths[i]))
		}
		sb.WriteString("\n")
	}

	return strings.TrimRight(sb.String(), "\n")
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func formatSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(size)/(1024*1024*1024))
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

// shellSplit splits a command string into tokens, respecting quoted strings.
func shellSplit(input string) []string {
	var tokens []string
	var current strings.Builder
	inSingle := false
	inDouble := false

	for i := 0; i < len(input); i++ {
		ch := input[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case ch == ' ' && !inSingle && !inDouble:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// parseFlags parses --key value and --key=value flags from args.
// Boolean flags (no value) are stored with value "true".
func parseFlags(args []string) map[string]string {
	flags := make(map[string]string)
	i := 0
	for i < len(args) {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			key := strings.TrimPrefix(a, "--")
			if idx := strings.Index(key, "="); idx >= 0 {
				flags[key[:idx]] = key[idx+1:]
				i++
				continue
			}
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i += 2
			} else {
				flags[key] = "true"
				i++
			}
		} else {
			i++
		}
	}
	return flags
}
