package mcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	ErrAlreadyRunning = errors.New("mcp: listener is already running")
	ErrNotRunning     = errors.New("mcp: listener is not running")
)

// Listener owns the MCP HTTP server and can be started and stopped repeatedly
// from the UI without leaking goroutines or racing the port.
//
// Three rules make that work, and each corresponds to a way this normally breaks:
//
//  1. Bind with net.Listen and then Serve, never ListenAndServe. Binding
//     synchronously means a port conflict is returned to the handler that asked
//     for the start — so the operator sees "address already in use" in the modal
//     rather than the UI reporting success while a goroutine logs the failure.
//
//  2. Build a fresh http.Server on every Start. A server that has been Shutdown
//     returns ErrServerClosed forever; reusing one is the single most common bug
//     in start/stop servers.
//
//  3. Stop waits for Serve to return, not just for Shutdown. Without that wait a
//     fast stop-then-start races "address already in use" and Running reports
//     stale state for a few milliseconds.
type Listener struct {
	mu      sync.Mutex
	srv     *http.Server
	ln      net.Listener
	done    chan struct{}
	port    int
	lastErr string
}

func NewListener() *Listener { return &Listener{} }

// Start binds the port and begins serving. It is an error to start a running
// listener; change the port by stopping first.
func (l *Listener) Start(port int, h http.Handler) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.srv != nil {
		return ErrAlreadyRunning
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		l.lastErr = err.Error()
		return err
	}

	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout must exceed http_batch's 120s hard wall-clock cap, or a
		// legitimate batch dies mid-write with no explanation.
		WriteTimeout:   150 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}
	done := make(chan struct{})

	l.srv, l.ln, l.done, l.port, l.lastErr = srv, ln, done, port, ""

	go func() {
		err := srv.Serve(ln)
		close(done)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.mu.Lock()
			l.lastErr = err.Error()
			l.srv, l.ln, l.done = nil, nil, nil
			l.mu.Unlock()
		}
	}()
	return nil
}

// Stop shuts the listener down and waits for Serve to return.
func (l *Listener) Stop(ctx context.Context) error {
	l.mu.Lock()
	srv, done := l.srv, l.done
	l.srv, l.ln, l.done = nil, nil, nil
	l.mu.Unlock()

	if srv == nil {
		return nil
	}
	err := srv.Shutdown(ctx)
	select {
	case <-done:
	case <-ctx.Done():
		// Shutdown's deadline passed with a connection still open. Close forces
		// it; an in-flight send is cut, which is the documented cost of stopping
		// the listener while a tool call is running.
		srv.Close() //nolint:errcheck
		<-done
	}
	return err
}

// Running reports whether the listener is serving, on which port, and the last
// error if it stopped unexpectedly.
func (l *Listener) Running() (running bool, port int, lastErr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.srv != nil, l.port, l.lastErr
}

// CloseOnContext arranges for process shutdown to stop the listener.
//
// Register this once, at construction, not per Start: a per-start registration
// accumulates a goroutine for every toggle over the process's lifetime.
func (l *Listener) CloseOnContext(ctx context.Context) {
	context.AfterFunc(ctx, func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		l.Stop(stopCtx) //nolint:errcheck
	})
}
