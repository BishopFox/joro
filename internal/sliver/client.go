package sliver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const defaultTimeout int64 = 60 // seconds

// tokenAuth implements grpc.PerRPCCredentials to attach the operator
// token to every RPC call as required by the Sliver teamserver.
type tokenAuth struct {
	token string
}

func (t tokenAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"Authorization": "Bearer " + t.token}, nil
}

func (t tokenAuth) RequireTransportSecurity() bool { return true }

// pendingDownload holds binary data temporarily for browser download.
type pendingDownload struct {
	data     []byte
	filename string
	created  time.Time
}

// Client manages a gRPC connection to a Sliver C2 teamserver.
type Client struct {
	mu              sync.Mutex
	conn            *grpc.ClientConn
	connected       bool
	config          OperatorConfig
	eventsCancel    context.CancelFunc
	activeSessionID   string
	activeSessionName string
	activeIsBeacon    bool
	onEvent         func(SliverEvent)
	downloads       sync.Map // id -> *pendingDownload
}

// Connect establishes an mTLS gRPC connection using the operator config.
func (c *Client) Connect(cfg OperatorConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return fmt.Errorf("already connected")
	}

	cert, err := tls.X509KeyPair([]byte(cfg.Certificate), []byte(cfg.PrivateKey))
	if err != nil {
		return fmt.Errorf("loading operator keypair: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(cfg.CACertificate)) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificate presented")
			}
			serverCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parsing server certificate: %w", err)
			}
			_, err = serverCert.Verify(x509.VerifyOptions{Roots: caCertPool})
			return err
		},
	}

	target := fmt.Sprintf("%s:%d", cfg.LHost, cfg.LPort)
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(tokenAuth{token: cfg.Token}),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodecCallOption{Codec: rawCodec{}},
			grpc.MaxCallRecvMsgSize(256*1024*1024),
		),
	)
	if err != nil {
		return fmt.Errorf("dialing %s: %w", target, err)
	}

	c.conn = conn
	c.connected = true
	c.config = cfg
	c.startEventsStream(conn)
	return nil
}

// startEventsStream opens a persistent server-streaming RPC to the Sliver
// teamserver's Events endpoint. Decoded events are forwarded via onEvent.
func (c *Client) startEventsStream(conn *grpc.ClientConn) {
	ctx, cancel := context.WithCancel(context.Background())
	c.eventsCancel = cancel

	go func() {
		stream, err := conn.NewStream(ctx,
			&grpc.StreamDesc{
				StreamName:   "Events",
				ServerStreams: true,
			},
			"/rpcpb.SliverRPC/Events",
		)
		if err != nil {
			return
		}

		req := []byte{}
		if err := stream.SendMsg(&req); err != nil {
			return
		}
		if err := stream.CloseSend(); err != nil {
			return
		}

		for {
			var msg []byte
			if err := stream.RecvMsg(&msg); err != nil {
				return
			}
			ev := decodeEvent(msg)
			if ev.EventType == "" {
				continue
			}
			c.mu.Lock()
			fn := c.onEvent
			c.mu.Unlock()
			if fn != nil {
				fn(ev)
			}
		}
	}()
}

// Disconnect closes the gRPC connection.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	if c.eventsCancel != nil {
		c.eventsCancel()
		c.eventsCancel = nil
	}

	err := c.conn.Close()
	c.conn = nil
	c.connected = false
	c.config = OperatorConfig{}
	c.activeSessionID = ""
	c.activeSessionName = ""
	c.activeIsBeacon = false
	return err
}

// ServerInfo returns the teamserver address and connection state.
func (c *Client) ServerInfo() (lhost string, lport int, connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.config.LHost, c.config.LPort, c.connected
}

// IsConnected returns whether the client has an active connection.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// SetActiveSession sets the active session for command dispatch.
func (c *Client) SetActiveSession(id, name string, isBeacon bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeSessionID = id
	c.activeSessionName = name
	c.activeIsBeacon = isBeacon
}

// GetActiveSession returns the active session ID, name, and whether it's a beacon.
func (c *Client) GetActiveSession() (id, name string, isBeacon bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeSessionID, c.activeSessionName, c.activeIsBeacon
}

// ClearActiveSession clears the active session.
func (c *Client) ClearActiveSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeSessionID = ""
	c.activeSessionName = ""
	c.activeIsBeacon = false
}

// SetOnEvent registers a callback that fires when the Sliver teamserver
// streams an event (new session, beacon, job change, etc.).
func (c *Client) SetOnEvent(fn func(SliverEvent)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEvent = fn
}

// connInfo returns the gRPC conn and connection state (caller must not hold lock).
func (c *Client) connInfo() (*grpc.ClientConn, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn, c.connected
}

// ---------------------------------------------------------------------------
// Download cache
// ---------------------------------------------------------------------------

// StoreDownload caches binary data for browser download. Returns a random ID.
func (c *Client) StoreDownload(data []byte, filename string) string {
	id := randomHex(16)
	c.downloads.Store(id, &pendingDownload{
		data:     data,
		filename: filename,
		created:  time.Now(),
	})
	// Clean up expired entries
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

// ---------------------------------------------------------------------------
// Session/Beacon listing (existing)
// ---------------------------------------------------------------------------

// ListSessions calls GetSessions on the Sliver teamserver.
func (c *Client) ListSessions(ctx context.Context) ([]SessionInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	err := conn.Invoke(ctx, "/rpcpb.SliverRPC/GetSessions", &req, &resp)
	if err != nil {
		return nil, fmt.Errorf("GetSessions RPC: %w", err)
	}

	sessions := decodeSessions(resp)
	if sessions == nil {
		sessions = []SessionInfo{}
	}
	return sessions, nil
}

// ListBeacons calls GetBeacons on the Sliver teamserver.
func (c *Client) ListBeacons(ctx context.Context) ([]BeaconInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	err := conn.Invoke(ctx, "/rpcpb.SliverRPC/GetBeacons", &req, &resp)
	if err != nil {
		return nil, fmt.Errorf("GetBeacons RPC: %w", err)
	}

	beacons := decodeBeacons(resp)
	if beacons == nil {
		beacons = []BeaconInfo{}
	}
	return beacons, nil
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

// Execute runs a command on a session via the Sliver teamserver.
func (c *Client) Execute(ctx context.Context, sessionID, command string, args []string, isBeacon bool) (stdout, stderr string, err error) {
	conn, connected := c.connInfo()
	if !connected {
		return "", "", fmt.Errorf("not connected")
	}

	req := encodeExecuteReq(command, args, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Execute", &req, &resp); err != nil {
		return "", "", fmt.Errorf("Execute RPC: %w", err)
	}

	result := decodeExecResponse(resp)
	if result.Err != "" {
		return "", "", fmt.Errorf("sliver error: %s", result.Err)
	}

	return string(result.Stdout), string(result.Stderr), nil
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

// Ls lists a directory on the target.
func (c *Client) Ls(ctx context.Context, sessionID, path string, isBeacon bool) (LsResult, error) {
	conn, connected := c.connInfo()
	if !connected {
		return LsResult{}, fmt.Errorf("not connected")
	}

	req := encodeLsReq(path, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Ls", &req, &resp); err != nil {
		return LsResult{}, fmt.Errorf("Ls RPC: %w", err)
	}

	result := decodeLsResp(resp)
	if result.Err != "" {
		return result, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result, nil
}

// Cd changes directory on the target. Returns new path.
func (c *Client) Cd(ctx context.Context, sessionID, path string, isBeacon bool) (string, error) {
	conn, connected := c.connInfo()
	if !connected {
		return "", fmt.Errorf("not connected")
	}

	req := encodeCdReq(path, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Cd", &req, &resp); err != nil {
		return "", fmt.Errorf("Cd RPC: %w", err)
	}

	result := decodePwdResp(resp)
	if result.Err != "" {
		return "", fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Path, nil
}

// Pwd returns the current working directory on the target.
func (c *Client) Pwd(ctx context.Context, sessionID string, isBeacon bool) (string, error) {
	conn, connected := c.connInfo()
	if !connected {
		return "", fmt.Errorf("not connected")
	}

	req := encodePwdReq(sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Pwd", &req, &resp); err != nil {
		return "", fmt.Errorf("Pwd RPC: %w", err)
	}

	result := decodePwdResp(resp)
	if result.Err != "" {
		return "", fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Path, nil
}

// Mkdir creates a directory on the target.
func (c *Client) Mkdir(ctx context.Context, sessionID, path string, isBeacon bool) (string, error) {
	conn, connected := c.connInfo()
	if !connected {
		return "", fmt.Errorf("not connected")
	}

	req := encodeMkdirReq(path, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Mkdir", &req, &resp); err != nil {
		return "", fmt.Errorf("Mkdir RPC: %w", err)
	}

	result := decodeMkdirResp(resp)
	if result.Err != "" {
		return "", fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Path, nil
}

// Rm removes a file or directory on the target.
func (c *Client) Rm(ctx context.Context, sessionID, path string, recursive, force bool, isBeacon bool) error {
	conn, connected := c.connInfo()
	if !connected {
		return fmt.Errorf("not connected")
	}

	req := encodeRmReq(path, recursive, force, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Rm", &req, &resp); err != nil {
		return fmt.Errorf("Rm RPC: %w", err)
	}

	result := decodeRmResp(resp)
	if result.Err != "" {
		return fmt.Errorf("sliver error: %s", result.Err)
	}
	return nil
}

// Download downloads a file from the target. Returns decompressed data and remote path.
func (c *Client) Download(ctx context.Context, sessionID, path string, isBeacon bool) ([]byte, string, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, "", fmt.Errorf("not connected")
	}

	req := encodeDownloadReq(path, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Download", &req, &resp); err != nil {
		return nil, "", fmt.Errorf("Download RPC: %w", err)
	}

	result := decodeDownloadResp(resp)
	if result.Err != "" {
		return nil, "", fmt.Errorf("sliver error: %s", result.Err)
	}
	if !result.Exists {
		return nil, "", fmt.Errorf("file does not exist: %s", path)
	}

	data, err := DecompressDownload(result)
	if err != nil {
		return nil, "", fmt.Errorf("decompressing: %w", err)
	}
	return data, result.Path, nil
}

// Upload uploads data to a remote path on the target.
func (c *Client) Upload(ctx context.Context, sessionID, remotePath string, data []byte, fileName string, isBeacon bool) (string, error) {
	conn, connected := c.connInfo()
	if !connected {
		return "", fmt.Errorf("not connected")
	}

	// Gzip-compress upload data (matching real Sliver client behavior)
	compressed, err := gzipCompress(data)
	if err != nil {
		return "", fmt.Errorf("compress upload data: %w", err)
	}

	req := encodeUploadReq(remotePath, compressed, "gzip", fileName, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Upload", &req, &resp); err != nil {
		return "", fmt.Errorf("Upload RPC: %w", err)
	}

	result := decodeUploadResp(resp)
	if result.Err != "" {
		return "", fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Path, nil
}

// ---------------------------------------------------------------------------
// Process
// ---------------------------------------------------------------------------

// Ps lists processes on the target.
func (c *Client) Ps(ctx context.Context, sessionID string, isBeacon bool) ([]ProcessInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodePsReq(sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Ps", &req, &resp); err != nil {
		return nil, fmt.Errorf("Ps RPC: %w", err)
	}

	result := decodePsResp(resp)
	if result.Err != "" {
		return nil, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Processes, nil
}

// Terminate kills a process on the target.
func (c *Client) Terminate(ctx context.Context, sessionID string, pid int32, isBeacon bool) error {
	conn, connected := c.connInfo()
	if !connected {
		return fmt.Errorf("not connected")
	}

	req := encodeTerminateReq(pid, true, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Terminate", &req, &resp); err != nil {
		return fmt.Errorf("Terminate RPC: %w", err)
	}

	result := decodeTerminateResp(resp)
	if result.Err != "" {
		return fmt.Errorf("sliver error: %s", result.Err)
	}
	return nil
}

// ProcessDump dumps memory of a process on the target.
func (c *Client) ProcessDump(ctx context.Context, sessionID string, pid int32, isBeacon bool) ([]byte, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodeProcessDumpReq(pid, int32(defaultTimeout), sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/ProcessDump", &req, &resp); err != nil {
		return nil, fmt.Errorf("ProcessDump RPC: %w", err)
	}

	result := decodeProcessDumpResp(resp)
	if result.Err != "" {
		return nil, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Data, nil
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

// Ifconfig returns network interfaces on the target.
func (c *Client) Ifconfig(ctx context.Context, sessionID string, isBeacon bool) ([]NetInterface, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodeIfconfigReq(sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Ifconfig", &req, &resp); err != nil {
		return nil, fmt.Errorf("Ifconfig RPC: %w", err)
	}

	result := decodeIfconfigResp(resp)
	if result.Err != "" {
		return nil, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Interfaces, nil
}

// Netstat returns network connections on the target.
func (c *Client) Netstat(ctx context.Context, sessionID string, tcp, udp, ip4, ip6, listening bool, isBeacon bool) ([]SockTabEntry, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodeNetstatReq(tcp, udp, ip4, ip6, listening, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Netstat", &req, &resp); err != nil {
		return nil, fmt.Errorf("Netstat RPC: %w", err)
	}

	result := decodeNetstatResp(resp)
	if result.Err != "" {
		return nil, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Entries, nil
}

// ---------------------------------------------------------------------------
// Recon
// ---------------------------------------------------------------------------

// Screenshot takes a screenshot on the target.
func (c *Client) Screenshot(ctx context.Context, sessionID string, isBeacon bool) ([]byte, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodeScreenshotReq(sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Screenshot", &req, &resp); err != nil {
		return nil, fmt.Errorf("Screenshot RPC: %w", err)
	}

	result := decodeScreenshotResp(resp)
	if result.Err != "" {
		return nil, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Data, nil
}

// CurrentTokenOwner returns the current user on the target (Windows).
func (c *Client) CurrentTokenOwner(ctx context.Context, sessionID string, isBeacon bool) (string, error) {
	conn, connected := c.connInfo()
	if !connected {
		return "", fmt.Errorf("not connected")
	}

	req := encodeCurrentTokenOwnerReq(sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/CurrentTokenOwner", &req, &resp); err != nil {
		return "", fmt.Errorf("CurrentTokenOwner RPC: %w", err)
	}

	result := decodeCurrentTokenOwnerResp(resp)
	if result.Err != "" {
		return "", fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Output, nil
}

// GetPrivs returns privileges on the target (Windows).
func (c *Client) GetPrivs(ctx context.Context, sessionID string, isBeacon bool) (GetPrivsResult, error) {
	conn, connected := c.connInfo()
	if !connected {
		return GetPrivsResult{}, fmt.Errorf("not connected")
	}

	req := encodeGetPrivsReq(sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/GetPrivs", &req, &resp); err != nil {
		return GetPrivsResult{}, fmt.Errorf("GetPrivs RPC: %w", err)
	}

	result := decodeGetPrivsResp(resp)
	if result.Err != "" {
		return result, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result, nil
}

// GetEnv returns environment variables on the target.
func (c *Client) GetEnv(ctx context.Context, sessionID, name string, isBeacon bool) ([]EnvEntry, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodeEnvReq(name, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/GetEnv", &req, &resp); err != nil {
		return nil, fmt.Errorf("GetEnv RPC: %w", err)
	}

	result := decodeEnvResp(resp)
	if result.Err != "" {
		return nil, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Variables, nil
}

// ---------------------------------------------------------------------------
// Execution (advanced)
// ---------------------------------------------------------------------------

// ExecuteAssembly runs a .NET assembly on the target.
func (c *Client) ExecuteAssembly(ctx context.Context, sessionID string, assembly []byte, arguments, process, arch string, isDLL bool, isBeacon bool) ([]byte, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodeExecuteAssemblyReq(assembly, arguments, process, isDLL, arch, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/ExecuteAssembly", &req, &resp); err != nil {
		return nil, fmt.Errorf("ExecuteAssembly RPC: %w", err)
	}

	result := decodeExecuteAssemblyResp(resp)
	if result.Err != "" {
		return nil, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Output, nil
}

// Sideload loads a shared library on the target.
func (c *Client) Sideload(ctx context.Context, sessionID string, data []byte, processName, args, entryPoint string, isBeacon bool) (string, error) {
	conn, connected := c.connInfo()
	if !connected {
		return "", fmt.Errorf("not connected")
	}

	req := encodeSideloadReq(data, processName, args, entryPoint, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Sideload", &req, &resp); err != nil {
		return "", fmt.Errorf("Sideload RPC: %w", err)
	}

	result := decodeSideloadResp(resp)
	if result.Err != "" {
		return "", fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Result, nil
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

// Kill terminates the current session on the target.
func (c *Client) Kill(ctx context.Context, sessionID string, isBeacon bool) error {
	conn, connected := c.connInfo()
	if !connected {
		return fmt.Errorf("not connected")
	}

	req := encodeKillReq(true, sessionID, defaultTimeout, isBeacon)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Kill", &req, &resp); err != nil {
		return fmt.Errorf("Kill RPC: %w", err)
	}

	errMsg := responseError(resp)
	if errMsg != "" {
		return fmt.Errorf("sliver error: %s", errMsg)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Server-level: Jobs
// ---------------------------------------------------------------------------

// GetJobs returns active jobs (listeners) on the teamserver.
func (c *Client) GetJobs(ctx context.Context) ([]JobInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/GetJobs", &req, &resp); err != nil {
		return nil, fmt.Errorf("GetJobs RPC: %w", err)
	}

	return decodeJobsResp(resp), nil
}

// KillJob stops a job on the teamserver.
func (c *Client) KillJob(ctx context.Context, jobID uint32) (bool, error) {
	conn, connected := c.connInfo()
	if !connected {
		return false, fmt.Errorf("not connected")
	}

	req := encodeKillJobReq(jobID)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/KillJob", &req, &resp); err != nil {
		return false, fmt.Errorf("KillJob RPC: %w", err)
	}

	result := decodeKillJobResp(resp)
	return result.Success, nil
}

// ---------------------------------------------------------------------------
// Server-level: Listeners
// ---------------------------------------------------------------------------

// StartMTLSListener starts an mTLS listener.
func (c *Client) StartMTLSListener(ctx context.Context, host string, port uint32) (uint32, error) {
	conn, connected := c.connInfo()
	if !connected {
		return 0, fmt.Errorf("not connected")
	}

	req := encodeMTLSListenerReq(host, port)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/StartMTLSListener", &req, &resp); err != nil {
		return 0, fmt.Errorf("StartMTLSListener RPC: %w", err)
	}

	result := decodeListenerJobResp(resp)
	if result.Err != "" {
		return 0, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.JobID, nil
}

// StartHTTPListener starts an HTTP listener.
func (c *Client) StartHTTPListener(ctx context.Context, domain, host string, port uint32) (uint32, error) {
	conn, connected := c.connInfo()
	if !connected {
		return 0, fmt.Errorf("not connected")
	}

	req := encodeHTTPListenerReq(domain, host, port, false)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/StartHTTPListener", &req, &resp); err != nil {
		return 0, fmt.Errorf("StartHTTPListener RPC: %w", err)
	}

	result := decodeListenerJobResp(resp)
	if result.Err != "" {
		return 0, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.JobID, nil
}

// StartHTTPSListener starts an HTTPS listener.
func (c *Client) StartHTTPSListener(ctx context.Context, domain, host string, port uint32) (uint32, error) {
	conn, connected := c.connInfo()
	if !connected {
		return 0, fmt.Errorf("not connected")
	}

	req := encodeHTTPListenerReq(domain, host, port, true)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/StartHTTPSListener", &req, &resp); err != nil {
		return 0, fmt.Errorf("StartHTTPSListener RPC: %w", err)
	}

	result := decodeListenerJobResp(resp)
	if result.Err != "" {
		return 0, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.JobID, nil
}

// StartDNSListener starts a DNS listener.
func (c *Client) StartDNSListener(ctx context.Context, domains []string, host string, port uint32) (uint32, error) {
	conn, connected := c.connInfo()
	if !connected {
		return 0, fmt.Errorf("not connected")
	}

	req := encodeDNSListenerReq(domains, false, host, port)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/StartDNSListener", &req, &resp); err != nil {
		return 0, fmt.Errorf("StartDNSListener RPC: %w", err)
	}

	result := decodeListenerJobResp(resp)
	if result.Err != "" {
		return 0, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.JobID, nil
}

// StartWGListener starts a WireGuard listener.
func (c *Client) StartWGListener(ctx context.Context, host string, port uint32) (uint32, error) {
	conn, connected := c.connInfo()
	if !connected {
		return 0, fmt.Errorf("not connected")
	}

	req := encodeWGListenerReq(host, port)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/StartWGListener", &req, &resp); err != nil {
		return 0, fmt.Errorf("StartWGListener RPC: %w", err)
	}

	result := decodeListenerJobResp(resp)
	if result.Err != "" {
		return 0, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.JobID, nil
}

// ---------------------------------------------------------------------------
// Server-level: Info & Management
// ---------------------------------------------------------------------------

// GetOperators returns connected operators.
func (c *Client) GetOperators(ctx context.Context) ([]OperatorInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/GetOperators", &req, &resp); err != nil {
		return nil, fmt.Errorf("GetOperators RPC: %w", err)
	}

	return decodeOperatorsResp(resp), nil
}

// GetVersion returns server version info.
func (c *Client) GetVersion(ctx context.Context) (VersionInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return VersionInfo{}, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/GetVersion", &req, &resp); err != nil {
		return VersionInfo{}, fmt.Errorf("GetVersion RPC: %w", err)
	}

	return decodeVersionResp(resp), nil
}

// ImplantBuilds returns all implant builds.
func (c *Client) ImplantBuilds(ctx context.Context) ([]ImplantBuildInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/ImplantBuilds", &req, &resp); err != nil {
		return nil, fmt.Errorf("ImplantBuilds RPC: %w", err)
	}

	return decodeImplantBuildsResp(resp), nil
}

// ImplantProfiles returns all implant profiles.
func (c *Client) ImplantProfiles(ctx context.Context) ([]ImplantProfileInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/ImplantProfiles", &req, &resp); err != nil {
		return nil, fmt.Errorf("ImplantProfiles RPC: %w", err)
	}

	return decodeImplantProfilesResp(resp), nil
}

// Hosts returns all known hosts.
func (c *Client) Hosts(ctx context.Context) ([]HostInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Hosts", &req, &resp); err != nil {
		return nil, fmt.Errorf("Hosts RPC: %w", err)
	}

	return decodeHostsResp(resp), nil
}

// LootAll returns all loot.
func (c *Client) LootAll(ctx context.Context) ([]LootInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/LootAll", &req, &resp); err != nil {
		return nil, fmt.Errorf("LootAll RPC: %w", err)
	}

	return decodeLootAllResp(resp), nil
}

// Websites returns all websites.
func (c *Client) Websites(ctx context.Context) ([]WebsiteInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Websites", &req, &resp); err != nil {
		return nil, fmt.Errorf("Websites RPC: %w", err)
	}

	return decodeWebsitesResp(resp), nil
}

// Canaries returns all canaries.
func (c *Client) Canaries(ctx context.Context) ([]CanaryInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Canaries", &req, &resp); err != nil {
		return nil, fmt.Errorf("Canaries RPC: %w", err)
	}

	return decodeCanariesResp(resp), nil
}

// Builders returns external builders.
func (c *Client) Builders(ctx context.Context) ([]BuilderInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := []byte{}
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Builders", &req, &resp); err != nil {
		return nil, fmt.Errorf("Builders RPC: %w", err)
	}

	return decodeBuildersResp(resp), nil
}

// Generate generates an implant binary.
func (c *Client) Generate(ctx context.Context, config ImplantGenerateConfig) ([]byte, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodeGenerateReq(config)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/Generate", &req, &resp); err != nil {
		return nil, fmt.Errorf("Generate RPC: %w", err)
	}

	result := decodeGenerateResp(resp)
	if result.Err != "" {
		return nil, fmt.Errorf("sliver error: %s", result.Err)
	}
	return result.Data, nil
}

// GetBeaconTasks returns tasks for a beacon.
func (c *Client) GetBeaconTasks(ctx context.Context, beaconID string) ([]BeaconTaskInfo, error) {
	conn, connected := c.connInfo()
	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	req := encodeBeaconTasksReq(beaconID)
	var resp []byte

	if err := conn.Invoke(ctx, "/rpcpb.SliverRPC/GetBeaconTasks", &req, &resp); err != nil {
		return nil, fmt.Errorf("GetBeaconTasks RPC: %w", err)
	}

	return decodeBeaconTasksResp(resp), nil
}
