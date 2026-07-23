// Package mythic implements a lightweight client for the Mythic C2 framework.
//
// Unlike the Sliver integration (gRPC + hand-rolled protowire), Mythic exposes a
// plain HTTP + GraphQL API, so this package needs only net/http + encoding/json
// (plus gorilla/websocket, already a dependency, as a client for the live-event
// subscription in subscription.go). No Mythic scripting library is vendored — the
// same "avoid the C2's giant dependency tree" stance as internal/sliver.
//
// The client operates at the *callback* level: it lists active callbacks, lets the
// operator select one, and issues commands as tasks to that callback. Installing
// agents / generating payloads are server-side operations and are out of scope.
//
// GraphQL field names target Mythic 3.3+. If a query errors with an unknown field,
// reconcile it against the running Mythic version (see docs.mythic-c2.net/scripting).
package mythic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	httpTimeout    = 30 * time.Second
	taskPollPeriod = 700 * time.Millisecond
	taskPollMax    = 60 * time.Second
	// fileDownloadPath is Mythic's direct file-content download route. Verify
	// against the target version if downloads fail (some releases use
	// /api/v1.4/files/download/{id}).
	fileDownloadPath = "/direct/download/"
)

// CallbackInfo is a single active Mythic callback (agent instance).
type CallbackInfo struct {
	ID           int    `json:"id"`
	DisplayID    int    `json:"display_id"`
	User         string `json:"user"`
	Host         string `json:"host"`
	PID          int    `json:"pid"`
	IP           string `json:"ip"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	LastCheckin  string `json:"last_checkin"`
	Description  string `json:"description"`
	PayloadType  string `json:"payload_type"`
}

// CommandInfo is a command loaded into a callback's agent.
type CommandInfo struct {
	Cmd         string `json:"cmd"`
	Description string `json:"description"`
}

// pendingDownload holds binary data temporarily for browser download.
type pendingDownload struct {
	data     []byte
	filename string
	created  time.Time
}

// Client manages an HTTP/GraphQL connection to a Mythic C2 server.
//
// Zero value is usable (mirrors sliver.Client); no constructor.
type Client struct {
	mu                 sync.Mutex
	http               *http.Client
	baseURL            string
	token              string // JWT (password flow) or API token
	isAPIToken         bool
	connected          bool
	activeCallbackID   int // display_id of the active callback
	activeCallbackName string
	subCancel          context.CancelFunc
	onEvent            func(MythicEvent)
	downloads          sync.Map // id -> *pendingDownload
}

// Connect authenticates to the Mythic server and starts the live-event stream.
//
// If APIToken is set it's used directly; otherwise Username/Password are exchanged
// at POST /auth for a JWT. The connection is validated with a trivial query before
// being marked connected.
func (c *Client) Connect(cfg Config) error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return fmt.Errorf("already connected")
	}
	base := strings.TrimRight(cfg.URL, "/")
	if base == "" {
		c.mu.Unlock()
		return fmt.Errorf("url is required")
	}
	c.baseURL = base
	c.http = &http.Client{
		Timeout: httpTimeout,
		// Mythic servers front GraphQL with a self-signed nginx cert; we skip
		// verification the same way the proxy's upstream dials do.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	c.mu.Unlock()

	if cfg.APIToken != "" {
		c.mu.Lock()
		c.token = cfg.APIToken
		c.isAPIToken = true
		c.mu.Unlock()
	} else {
		if cfg.Username == "" || cfg.Password == "" {
			c.reset()
			return fmt.Errorf("username and password (or an API token) are required")
		}
		token, err := c.login(base, cfg.Username, cfg.Password)
		if err != nil {
			c.reset()
			return fmt.Errorf("authentication failed: %w", err)
		}
		c.mu.Lock()
		c.token = token
		c.isAPIToken = false
		c.mu.Unlock()
	}

	// Validate credentials with a trivial query before committing.
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	var probe struct {
		Callback []struct {
			ID int `json:"id"`
		} `json:"callback"`
	}
	if err := c.graphql(ctx, `query Probe { callback(limit: 1) { id } }`, nil, &probe); err != nil {
		c.reset()
		return fmt.Errorf("could not reach Mythic GraphQL: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	c.startEventsStream()
	return nil
}

// login exchanges username/password for a JWT access token at POST /auth.
func (c *Client) login(base, username, password string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"username":          username,
		"password":          password,
		"scripting_version": "joro",
	})
	req, err := http.NewRequest(http.MethodPost, base+"/auth", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		if out.Error != "" {
			return "", fmt.Errorf("%s", out.Error)
		}
		return "", fmt.Errorf("no access_token in response")
	}
	return out.AccessToken, nil
}

// graphql POSTs a query/mutation to the Hasura GraphQL endpoint and unmarshals
// the "data" field into out. Auth is a Bearer JWT or an apitoken header.
func (c *Client) graphql(ctx context.Context, query string, vars map[string]any, out any) error {
	c.mu.Lock()
	base, token, isAPI, httpc := c.baseURL, c.token, c.isAPIToken, c.http
	c.mu.Unlock()
	if httpc == nil {
		return fmt.Errorf("not connected")
	}

	payload := map[string]any{"query": query}
	if vars != nil {
		payload["variables"] = vars
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/graphql/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if isAPI {
		req.Header.Set("apitoken", token)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("graphql status %d", resp.StatusCode)
	}

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	if len(envelope.Errors) > 0 {
		return fmt.Errorf("%s", envelope.Errors[0].Message)
	}
	if out != nil && len(envelope.Data) > 0 {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return err
		}
	}
	return nil
}

// Disconnect tears down the event stream and clears all connection state.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected {
		return nil
	}
	c.resetLocked()
	return nil
}

// reset clears connection state (acquires the lock).
func (c *Client) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked()
}

// resetLocked clears connection state; caller must hold c.mu.
func (c *Client) resetLocked() {
	if c.subCancel != nil {
		c.subCancel()
		c.subCancel = nil
	}
	c.http = nil
	c.baseURL = ""
	c.token = ""
	c.isAPIToken = false
	c.connected = false
	c.activeCallbackID = 0
	c.activeCallbackName = ""
}

// ServerInfo returns the Mythic base URL and connection state.
func (c *Client) ServerInfo() (url string, connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.baseURL, c.connected
}

// IsConnected reports whether the client has an authenticated connection.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// SetActiveCallback sets the callback that commands are tasked to.
func (c *Client) SetActiveCallback(displayID int, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeCallbackID = displayID
	c.activeCallbackName = name
}

// GetActiveCallback returns the active callback's display_id and name.
func (c *Client) GetActiveCallback() (displayID int, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeCallbackID, c.activeCallbackName
}

// ClearActiveCallback backgrounds the active callback.
func (c *Client) ClearActiveCallback() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeCallbackID = 0
	c.activeCallbackName = ""
}

// SetOnEvent registers a callback fired when Mythic streams a new callback event.
func (c *Client) SetOnEvent(fn func(MythicEvent)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEvent = fn
}

// ---------------------------------------------------------------------------
// Domain operations
// ---------------------------------------------------------------------------

// ListCallbacks returns all active callbacks.
func (c *Client) ListCallbacks(ctx context.Context) ([]CallbackInfo, error) {
	var data struct {
		Callback []struct {
			ID           int    `json:"id"`
			DisplayID    int    `json:"display_id"`
			User         string `json:"user"`
			Host         string `json:"host"`
			PID          int    `json:"pid"`
			IP           string `json:"ip"`
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			LastCheckin  string `json:"last_checkin"`
			Description  string `json:"description"`
			Payload      struct {
				PayloadType struct {
					Name string `json:"name"`
				} `json:"payloadtype"`
			} `json:"payload"`
		} `json:"callback"`
	}
	q := `query Callbacks {
		callback(where: {active: {_eq: true}}, order_by: {display_id: asc}) {
			id display_id user host pid ip os architecture last_checkin description
			payload { payloadtype { name } }
		}
	}`
	if err := c.graphql(ctx, q, nil, &data); err != nil {
		return nil, err
	}
	out := make([]CallbackInfo, 0, len(data.Callback))
	for _, cb := range data.Callback {
		out = append(out, CallbackInfo{
			ID: cb.ID, DisplayID: cb.DisplayID, User: cb.User, Host: cb.Host,
			PID: cb.PID, IP: cb.IP, OS: cb.OS, Architecture: cb.Architecture,
			LastCheckin: cb.LastCheckin, Description: cb.Description,
			PayloadType: cb.Payload.PayloadType.Name,
		})
	}
	return out, nil
}

// LoadedCommands returns the commands loaded into a callback's agent, used to
// render a per-callback `help` reflecting the real agent capabilities.
func (c *Client) LoadedCommands(ctx context.Context, callbackDisplayID int) ([]CommandInfo, error) {
	var data struct {
		Loadedcommands []struct {
			Command struct {
				Cmd         string `json:"cmd"`
				Description string `json:"description"`
			} `json:"command"`
		} `json:"loadedcommands"`
	}
	q := `query LoadedCommands($id: Int!) {
		loadedcommands(where: {callback: {display_id: {_eq: $id}}}, order_by: {command: {cmd: asc}}) {
			command { cmd description }
		}
	}`
	if err := c.graphql(ctx, q, map[string]any{"id": callbackDisplayID}, &data); err != nil {
		return nil, err
	}
	out := make([]CommandInfo, 0, len(data.Loadedcommands))
	for _, lc := range data.Loadedcommands {
		out = append(out, CommandInfo{Cmd: lc.Command.Cmd, Description: lc.Command.Description})
	}
	return out, nil
}

// IssueTask creates a task on a callback and returns its display_id.
func (c *Client) IssueTask(ctx context.Context, callbackDisplayID int, command, params string) (int, error) {
	var data struct {
		CreateTask struct {
			Status    string `json:"status"`
			ID        int    `json:"id"`
			DisplayID int    `json:"display_id"`
			Error     string `json:"error"`
		} `json:"createTask"`
	}
	q := `mutation IssueTask($callback_id: Int!, $command: String!, $params: String!) {
		createTask(callback_id: $callback_id, command: $command, params: $params) {
			status id display_id error
		}
	}`
	vars := map[string]any{"callback_id": callbackDisplayID, "command": command, "params": params}
	if err := c.graphql(ctx, q, vars, &data); err != nil {
		return 0, err
	}
	if strings.EqualFold(data.CreateTask.Status, "error") || data.CreateTask.Error != "" {
		return 0, fmt.Errorf("%s", data.CreateTask.Error)
	}
	return data.CreateTask.DisplayID, nil
}

// WaitForTaskOutput polls a task until it completes (or the deadline is hit) and
// returns the concatenated, base64-decoded responses.
func (c *Client) WaitForTaskOutput(ctx context.Context, taskDisplayID int) (string, error) {
	deadline := time.Now().Add(taskPollMax)
	q := `query TaskOutput($id: Int!) {
		task(where: {display_id: {_eq: $id}}) {
			status completed
			responses(order_by: {id: asc}) { response }
		}
	}`
	for {
		var data struct {
			Task []struct {
				Status    string `json:"status"`
				Completed bool   `json:"completed"`
				Responses []struct {
					Response string `json:"response"`
				} `json:"responses"`
			} `json:"task"`
		}
		if err := c.graphql(ctx, q, map[string]any{"id": taskDisplayID}, &data); err != nil {
			return "", err
		}
		if len(data.Task) > 0 {
			t := data.Task[0]
			if t.Completed || strings.Contains(strings.ToLower(t.Status), "error") {
				var sb strings.Builder
				for _, r := range t.Responses {
					sb.WriteString(decodeResponse(r.Response))
				}
				out := sb.String()
				if strings.Contains(strings.ToLower(t.Status), "error") && out == "" {
					return "", fmt.Errorf("task errored: %s", t.Status)
				}
				return out, nil
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timed out waiting for task %d output", taskDisplayID)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(taskPollPeriod):
		}
	}
}

// ListTasks returns recent tasks for a callback (most recent first).
func (c *Client) ListTasks(ctx context.Context, callbackDisplayID, limit int) ([]TaskInfo, error) {
	var data struct {
		Task []struct {
			DisplayID     int    `json:"display_id"`
			CommandName   string `json:"command_name"`
			OriginalParams string `json:"original_params"`
			Status        string `json:"status"`
			Operator      struct {
				Username string `json:"username"`
			} `json:"operator"`
		} `json:"task"`
	}
	q := `query Tasks($id: Int!, $limit: Int!) {
		task(where: {callback: {display_id: {_eq: $id}}}, order_by: {display_id: desc}, limit: $limit) {
			display_id command_name original_params status operator { username }
		}
	}`
	vars := map[string]any{"id": callbackDisplayID, "limit": limit}
	if err := c.graphql(ctx, q, vars, &data); err != nil {
		return nil, err
	}
	out := make([]TaskInfo, 0, len(data.Task))
	for _, t := range data.Task {
		out = append(out, TaskInfo{
			DisplayID: t.DisplayID, Command: t.CommandName, Params: t.OriginalParams,
			Status: t.Status, Operator: t.Operator.Username,
		})
	}
	return out, nil
}

// TaskInfo is a summary row for the `tasks` command.
type TaskInfo struct {
	DisplayID int
	Command   string
	Params    string
	Status    string
	Operator  string
}

// DownloadFileForTask locates the file registered by a completed download task
// and fetches its bytes. Returns (data, filename).
func (c *Client) DownloadFileForTask(ctx context.Context, taskDisplayID int) ([]byte, string, error) {
	var data struct {
		Filemeta []struct {
			AgentFileID string `json:"agent_file_id"`
			Filename    string `json:"filename_text"`
		} `json:"filemeta"`
	}
	q := `query FileForTask($id: Int!) {
		filemeta(where: {task: {display_id: {_eq: $id}}, is_download_from_agent: {_eq: true}}, order_by: {id: desc}, limit: 1) {
			agent_file_id filename_text
		}
	}`
	if err := c.graphql(ctx, q, map[string]any{"id": taskDisplayID}, &data); err != nil {
		return nil, "", err
	}
	if len(data.Filemeta) == 0 {
		return nil, "", fmt.Errorf("no downloaded file registered for task %d", taskDisplayID)
	}
	fm := data.Filemeta[0]
	content, err := c.fetchFile(ctx, fm.AgentFileID)
	if err != nil {
		return nil, "", err
	}
	name := fm.Filename
	if name == "" {
		name = "download"
	}
	return content, name, nil
}

// fetchFile downloads registered file content by agent_file_id.
func (c *Client) fetchFile(ctx context.Context, agentFileID string) ([]byte, error) {
	c.mu.Lock()
	base, token, isAPI, httpc := c.baseURL, c.token, c.isAPIToken, c.http
	c.mu.Unlock()
	if httpc == nil {
		return nil, fmt.Errorf("not connected")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+fileDownloadPath+agentFileID, nil)
	if err != nil {
		return nil, err
	}
	if isAPI {
		req.Header.Set("apitoken", token)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("file download status %d", resp.StatusCode)
	}
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RegisterAndUpload registers a file with Mythic and issues an upload task placing
// it at remotePath on the active callback. Returns the remote path on success.
func (c *Client) RegisterAndUpload(ctx context.Context, callbackDisplayID int, remotePath, filename string, data []byte) (string, error) {
	fileID, err := c.registerFile(ctx, filename, data)
	if err != nil {
		return "", fmt.Errorf("registering file: %w", err)
	}
	params, _ := json.Marshal(map[string]any{"file": fileID, "remote_path": remotePath})
	taskID, err := c.IssueTask(ctx, callbackDisplayID, "upload", string(params))
	if err != nil {
		return "", err
	}
	if _, err := c.WaitForTaskOutput(ctx, taskID); err != nil {
		return "", err
	}
	return remotePath, nil
}

// registerFile uploads file bytes to Mythic's scripting file-registration endpoint
// and returns the resulting file UUID.
func (c *Client) registerFile(ctx context.Context, filename string, data []byte) (string, error) {
	var out struct {
		RegisterFile struct {
			Status string `json:"status"`
			Error  string `json:"error"`
			FileID string `json:"agent_file_id"`
		} `json:"registerFileInChunk"`
	}
	// Mythic registers scripting files via a chunked mutation; for typical
	// operator payloads a single base64 chunk suffices.
	q := `mutation RegisterFile($file: String!, $name: String!, $total: Int!, $chunk: Int!) {
		registerFileInChunk(file_content: $file, total_chunks: $total, chunk_number: $chunk, full_path: $name) {
			status error agent_file_id
		}
	}`
	vars := map[string]any{
		"file":  encodeBase64(data),
		"name":  filename,
		"total": 1,
		"chunk": 1,
	}
	if err := c.graphql(ctx, q, vars, &out); err != nil {
		return "", err
	}
	if strings.EqualFold(out.RegisterFile.Status, "error") || out.RegisterFile.FileID == "" {
		if out.RegisterFile.Error != "" {
			return "", fmt.Errorf("%s", out.RegisterFile.Error)
		}
		return "", fmt.Errorf("file registration returned no id")
	}
	return out.RegisterFile.FileID, nil
}

// ---------------------------------------------------------------------------
// Download cache (mirrors sliver.Client)
// ---------------------------------------------------------------------------

// StoreDownload caches binary data for browser download. Returns a random ID.
func (c *Client) StoreDownload(data []byte, filename string) string {
	id := randomHex(16)
	c.downloads.Store(id, &pendingDownload{data: data, filename: filename, created: time.Now()})
	c.downloads.Range(func(key, value any) bool {
		dl := value.(*pendingDownload)
		if time.Since(dl.created) > 60*time.Second {
			c.downloads.Delete(key)
		}
		return true
	})
	return id
}

// GetDownload retrieves and removes a cached download.
func (c *Client) GetDownload(id string) ([]byte, string, bool) {
	val, ok := c.downloads.LoadAndDelete(id)
	if !ok {
		return nil, "", false
	}
	dl := val.(*pendingDownload)
	return dl.data, dl.filename, true
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
