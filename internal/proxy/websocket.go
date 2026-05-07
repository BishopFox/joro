package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// WebSocket opcodes per RFC 6455.
const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

const wsMaxPayloadSize = 16 << 20 // 16MB sanity limit

// WSFrame represents a single WebSocket frame.
type WSFrame struct {
	FIN     bool
	Opcode  byte
	Masked  bool
	Payload []byte
}

// IsControl returns true for close/ping/pong frames.
func (f *WSFrame) IsControl() bool {
	return f.Opcode >= wsOpClose
}

// ReadFrame reads a single WebSocket frame from r.
func ReadFrame(r io.Reader) (*WSFrame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	f := &WSFrame{
		FIN:    header[0]&0x80 != 0,
		Opcode: header[0] & 0x0F,
		Masked: header[1]&0x80 != 0,
	}

	payloadLen := uint64(header[1] & 0x7F)
	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		payloadLen = binary.BigEndian.Uint64(ext)
	}

	if payloadLen > wsMaxPayloadSize {
		return nil, fmt.Errorf("websocket frame too large: %d bytes", payloadLen)
	}

	var maskKey [4]byte
	if f.Masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return nil, err
		}
	}

	f.Payload = make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}

	// Unmask in-place.
	if f.Masked {
		for i := range f.Payload {
			f.Payload[i] ^= maskKey[i%4]
		}
	}

	return f, nil
}

// WriteFrame writes a WebSocket frame to w. If masked is true, a random mask is applied.
func WriteFrame(w io.Writer, f *WSFrame, masked bool) error {
	var header [2]byte
	if f.FIN {
		header[0] |= 0x80
	}
	header[0] |= f.Opcode & 0x0F

	payloadLen := len(f.Payload)
	if masked {
		header[1] |= 0x80
	}

	switch {
	case payloadLen <= 125:
		header[1] |= byte(payloadLen)
		if _, err := w.Write(header[:]); err != nil {
			return err
		}
	case payloadLen <= 65535:
		header[1] |= 126
		if _, err := w.Write(header[:]); err != nil {
			return err
		}
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(payloadLen))
		if _, err := w.Write(ext); err != nil {
			return err
		}
	default:
		header[1] |= 127
		if _, err := w.Write(header[:]); err != nil {
			return err
		}
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(payloadLen))
		if _, err := w.Write(ext); err != nil {
			return err
		}
	}

	if masked {
		var maskKey [4]byte
		readRand(maskKey[:])
		if _, err := w.Write(maskKey[:]); err != nil {
			return err
		}
		masked := make([]byte, payloadLen)
		for i, b := range f.Payload {
			masked[i] = b ^ maskKey[i%4]
		}
		_, err := w.Write(masked)
		return err
	}

	_, err := w.Write(f.Payload)
	return err
}

// isWebSocketUpgrade checks if an HTTP request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}
