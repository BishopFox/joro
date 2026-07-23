package mythic

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// CommandResult is the result of dispatching one REPL line. Mirrors
// sliver.CommandResult but keyed on callbacks rather than sessions.
type CommandResult struct {
	Output          string `json:"output"`
	Error           string `json:"error,omitempty"`
	DownloadID      string `json:"downloadId,omitempty"`
	Filename        string `json:"filename,omitempty"`
	CallbackChanged bool   `json:"callbackChanged,omitempty"`
	CallbackID      int    `json:"callbackId,omitempty"`
	CallbackName    string `json:"callbackName,omitempty"`
	Disconnected    bool   `json:"disconnected,omitempty"`
}

// replVerbs are the Joro-side commands handled here (not passed to the agent).
const replVerbs = "callbacks, use <id>, background, tasks, download <path>, upload <path>, clear, exit"

// Dispatch parses and executes one REPL line against the Mythic server.
func (c *Client) Dispatch(ctx context.Context, input string) CommandResult {
	parts := shellSplit(input)
	if len(parts) == 0 {
		return CommandResult{}
	}
	verb := strings.ToLower(parts[0])

	switch verb {
	case "help":
		return c.cmdHelp(ctx)
	case "callbacks", "sessions":
		return c.cmdCallbacks(ctx)
	case "use":
		return c.cmdUse(ctx, parts)
	case "background", "bg":
		c.ClearActiveCallback()
		return CommandResult{Output: "[*] Backgrounded active callback", CallbackChanged: true}
	case "tasks":
		return c.cmdTasks(ctx)
	case "download":
		return c.cmdDownload(ctx, parts)
	case "exit", "quit":
		return CommandResult{Output: "[*] Disconnected from Mythic", Disconnected: true}
	default:
		return c.cmdTask(ctx, parts[0], input)
	}
}

func (c *Client) cmdHelp(ctx context.Context) CommandResult {
	var sb strings.Builder
	sb.WriteString("Joro commands: ")
	sb.WriteString(replVerbs)
	sb.WriteString("\n")

	id, name := c.GetActiveCallback()
	if id == 0 {
		sb.WriteString("\nNo active callback. Run 'callbacks' then 'use <display_id>' to select one.")
		return CommandResult{Output: sb.String()}
	}

	cmds, err := c.LoadedCommands(ctx, id)
	if err != nil {
		return CommandResult{Output: sb.String(), Error: fmt.Sprintf("loading commands: %v", err)}
	}
	sb.WriteString(fmt.Sprintf("\nLoaded commands for callback %d (%s):\n", id, name))
	if len(cmds) == 0 {
		sb.WriteString("  (none loaded)")
	}
	for _, cm := range cmds {
		if cm.Description != "" {
			sb.WriteString(fmt.Sprintf("  %-20s %s\n", cm.Cmd, cm.Description))
		} else {
			sb.WriteString(fmt.Sprintf("  %s\n", cm.Cmd))
		}
	}
	return CommandResult{Output: strings.TrimRight(sb.String(), "\n")}
}

func (c *Client) cmdCallbacks(ctx context.Context) CommandResult {
	cbs, err := c.ListCallbacks(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(cbs) == 0 {
		return CommandResult{Output: "[*] No active callbacks"}
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-4s %-10s %-18s %-16s %-10s %s\n", "ID", "TYPE", "USER", "HOST", "OS", "IP"))
	for _, cb := range cbs {
		sb.WriteString(fmt.Sprintf("%-4d %-10s %-18s %-16s %-10s %s\n",
			cb.DisplayID, cb.PayloadType, truncate(cb.User, 18), truncate(cb.Host, 16), truncate(cb.OS, 10), cb.IP))
	}
	return CommandResult{Output: strings.TrimRight(sb.String(), "\n")}
}

func (c *Client) cmdUse(ctx context.Context, parts []string) CommandResult {
	if len(parts) < 2 {
		return CommandResult{Error: "Usage: use <display_id>"}
	}
	displayID, err := strconv.Atoi(parts[1])
	if err != nil {
		return CommandResult{Error: fmt.Sprintf("invalid callback id: %s", parts[1])}
	}
	cbs, err := c.ListCallbacks(ctx)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	for _, cb := range cbs {
		if cb.DisplayID == displayID {
			name := cb.PayloadType
			if cb.Host != "" {
				name = fmt.Sprintf("%s@%s", cb.PayloadType, cb.Host)
			}
			c.SetActiveCallback(displayID, name)
			return CommandResult{
				Output:          fmt.Sprintf("[*] Active callback set to %d (%s)", displayID, name),
				CallbackChanged: true, CallbackID: displayID, CallbackName: name,
			}
		}
	}
	return CommandResult{Error: fmt.Sprintf("no active callback with id %d", displayID)}
}

func (c *Client) cmdTasks(ctx context.Context) CommandResult {
	id, _ := c.GetActiveCallback()
	if id == 0 {
		return CommandResult{Error: "no active callback — use <display_id> first"}
	}
	tasks, err := c.ListTasks(ctx, id, 20)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if len(tasks) == 0 {
		return CommandResult{Output: "[*] No tasks yet for this callback"}
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-5s %-14s %-12s %s\n", "TASK", "COMMAND", "STATUS", "PARAMS"))
	for _, t := range tasks {
		sb.WriteString(fmt.Sprintf("%-5d %-14s %-12s %s\n",
			t.DisplayID, truncate(t.Command, 14), truncate(t.Status, 12), truncate(t.Params, 40)))
	}
	return CommandResult{Output: strings.TrimRight(sb.String(), "\n")}
}

func (c *Client) cmdDownload(ctx context.Context, parts []string) CommandResult {
	id, _ := c.GetActiveCallback()
	if id == 0 {
		return CommandResult{Error: "no active callback — use <display_id> first"}
	}
	if len(parts) < 2 {
		return CommandResult{Error: "Usage: download <remote_path>"}
	}
	remotePath := strings.Join(parts[1:], " ")
	taskID, err := c.IssueTask(ctx, id, "download", remotePath)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	if _, err := c.WaitForTaskOutput(ctx, taskID); err != nil {
		return CommandResult{Error: err.Error()}
	}
	data, filename, err := c.DownloadFileForTask(ctx, taskID)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	dlID := c.StoreDownload(data, filename)
	return CommandResult{
		Output:     fmt.Sprintf("[*] Downloaded %s (%d bytes)", filename, len(data)),
		DownloadID: dlID, Filename: filename,
	}
}

// cmdTask issues an arbitrary command to the active callback as a Mythic task and
// waits for its output. command is the verb; fullInput is the whole line so the
// remainder (verbatim) becomes the task params.
func (c *Client) cmdTask(ctx context.Context, command, fullInput string) CommandResult {
	id, _ := c.GetActiveCallback()
	if id == 0 {
		return CommandResult{Error: "no active callback — run 'callbacks' then 'use <display_id>'"}
	}
	params := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(fullInput), command))
	taskID, err := c.IssueTask(ctx, id, command, params)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	out, err := c.WaitForTaskOutput(ctx, taskID)
	if err != nil {
		return CommandResult{Error: err.Error()}
	}
	return CommandResult{Output: out}
}

// shellSplit splits a command line on whitespace, honoring single/double quotes.
func shellSplit(s string) []string {
	var parts []string
	var cur strings.Builder
	var quote rune
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inWord {
				parts = append(parts, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		parts = append(parts, cur.String())
	}
	return parts
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
