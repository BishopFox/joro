package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Server wraps an HTTP proxy listener.
type Server struct {
	bindAddr string
	port     int
	handler  *Handler
	srv      *http.Server
}

// NewServer creates a proxy Server on the given address and port.
func NewServer(bindAddr string, port int, handler *Handler) *Server {
	return &Server{bindAddr: bindAddr, port: port, handler: handler}
}

// Start begins listening and blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.srv = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.bindAddr, s.port),
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(shutCtx) //nolint:errcheck
	}()

	if err := s.srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}
