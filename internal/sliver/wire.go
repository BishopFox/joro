package sliver

// wire.go provides minimal protobuf wire encoding/decoding for the Sliver gRPC
// messages we need, avoiding the full protobuf/sliver dependency tree.
//
// Field numbers are taken from the Sliver protobuf definitions:
// https://github.com/BishopFox/sliver/tree/master/protobuf
// Tested against Sliver v1.5.x

import (
	"compress/gzip"
	"bytes"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protowire"
)

// rawCodec is a gRPC codec that passes raw bytes, allowing us to do our own
// protobuf encoding/decoding.
type rawCodec struct{}

func (rawCodec) Marshal(v interface{}) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("rawCodec: expected *[]byte, got %T", v)
	}
	return *b, nil
}

func (rawCodec) Unmarshal(data []byte, v interface{}) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec: expected *[]byte, got %T", v)
	}
	*b = append((*b)[:0], data...)
	return nil
}

func (rawCodec) Name() string { return "proto" }

// ---------------------------------------------------------------------------
// Reusable encoding helpers
// ---------------------------------------------------------------------------

// encodeRequestSubmsg encodes a commonpb.Request submessage.
// Request: Timeout=2(varint), SessionID=9(string), BeaconID=8(string)
func encodeRequestSubmsg(sessionID string, timeout int64, isBeacon bool) []byte {
	var sub []byte
	// Async=1 (bool) — must be true for beacon commands
	if isBeacon {
		sub = protowire.AppendTag(sub, 1, protowire.VarintType)
		sub = protowire.AppendVarint(sub, 1)
	}
	// Timeout=2
	if timeout > 0 {
		sub = protowire.AppendTag(sub, 2, protowire.VarintType)
		sub = protowire.AppendVarint(sub, uint64(timeout))
	}
	// BeaconID=8
	if isBeacon && sessionID != "" {
		sub = protowire.AppendTag(sub, 8, protowire.BytesType)
		sub = protowire.AppendString(sub, sessionID)
	}
	// SessionID=9
	if !isBeacon && sessionID != "" {
		sub = protowire.AppendTag(sub, 9, protowire.BytesType)
		sub = protowire.AppendString(sub, sessionID)
	}
	return sub
}

// appendRequestField appends the Request submessage at field 9.
func appendRequestField(b []byte, sessionID string, timeout int64, isBeacon bool) []byte {
	sub := encodeRequestSubmsg(sessionID, timeout, isBeacon)
	b = protowire.AppendTag(b, 9, protowire.BytesType)
	b = protowire.AppendBytes(b, sub)
	return b
}

// encodeSimpleReq encodes a request with just a Request submessage (no other fields).
func encodeSimpleReq(sessionID string, timeout int64, isBeacon bool) []byte {
	return appendRequestField(nil, sessionID, timeout, isBeacon)
}

// encodePathReq encodes a request with Path at field 1 and Request at field 9.
func encodePathReq(path, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, path)
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// ---------------------------------------------------------------------------
// Reusable decoding helpers
// ---------------------------------------------------------------------------

// skipField advances past one protobuf field value of the given wire type.
// Returns the remaining data and true on success.
func skipField(data []byte, typ protowire.Type) ([]byte, bool) {
	switch typ {
	case protowire.VarintType:
		_, n := protowire.ConsumeVarint(data)
		if n < 0 {
			return data, false
		}
		return data[n:], true
	case protowire.Fixed32Type:
		if len(data) < 4 {
			return data, false
		}
		return data[4:], true
	case protowire.Fixed64Type:
		if len(data) < 8 {
			return data, false
		}
		return data[8:], true
	case protowire.BytesType:
		_, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return data, false
		}
		return data[n:], true
	default:
		return data, false
	}
}

// decodeResponseErr extracts the Err string (field 1) from a commonpb.Response submessage.
func decodeResponseErr(data []byte) string {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return ""
			}
			return string(v)
		}

		var ok bool
		data, ok = skipField(data, typ)
		if !ok {
			return ""
		}
	}
	return ""
}

// decodeStringField1 extracts a string at field 1 from a protobuf message.
func decodeStringField1(data []byte) string {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return ""
			}
			return string(v)
		}

		var ok bool
		data, ok = skipField(data, typ)
		if !ok {
			return ""
		}
	}
	return ""
}

// responseError checks a message for a Response submessage at field 9 and
// returns the error string if present.
func responseError(data []byte) string {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 9 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return ""
			}
			return decodeResponseErr(v)
		}

		var ok bool
		data, ok = skipField(data, typ)
		if !ok {
			return ""
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Execute (existing, refactored)
// ---------------------------------------------------------------------------

// encodeExecuteReq encodes a sliverpb.ExecuteReq message.
// Field numbers: Path=1, Args=2, Output=3, Request=9
func encodeExecuteReq(path string, args []string, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte

	// Path (field 1, string)
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, path)

	// Args (field 2, repeated string)
	for _, arg := range args {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, arg)
	}

	// Output = true (field 3, bool/varint)
	b = protowire.AppendTag(b, 3, protowire.VarintType)
	b = protowire.AppendVarint(b, 1)

	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// ExecResult holds decoded sliverpb.Execute response.
type ExecResult struct {
	Status uint32
	Stdout []byte
	Stderr []byte
	Pid    uint32
	Err    string // from embedded commonpb.Response
}

// decodeExecResponse decodes a sliverpb.Execute message.
// Fields: Status=1(varint), Stdout=2(bytes), Stderr=3(bytes), Pid=4(varint), Response=9(submsg)
func decodeExecResponse(data []byte) ExecResult {
	var r ExecResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Status = uint32(v)
			case 4:
				r.Pid = uint32(v)
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 2:
				r.Stdout = append([]byte(nil), v...)
			case 3:
				r.Stderr = append([]byte(nil), v...)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// SliverEvent holds a decoded clientpb.Event from the Events stream.
type SliverEvent struct {
	EventType string      `json:"eventType"`
	Session   SessionInfo `json:"session,omitempty"`
	Beacon    BeaconInfo  `json:"beacon,omitempty"`
	JobID     uint32      `json:"jobId,omitempty"`
	JobName   string      `json:"jobName,omitempty"`
	Err       string      `json:"err,omitempty"`
}

// decodeEvent decodes clientpb.Event: EventType=1, Session=2, Job=3, Data=5, Err=6
func decodeEvent(data []byte) SliverEvent {
	var ev SliverEvent
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]
		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return ev
			}
			_ = v
			data = data[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return ev
			}
			switch num {
			case 1: // EventType
				ev.EventType = string(v)
			case 2: // Session submessage
				ev.Session = decodeSession(v)
			case 3: // Job submessage — extract ID=1(varint) and Name=2(string)
				ev.JobID, ev.JobName = decodeJobSummary(v)
			case 5: // Data — for beacon events, contains marshaled Beacon
				if ev.EventType == "beacon-registered" || ev.EventType == "beacon-taskresult" {
					ev.Beacon = decodeBeacon(v)
				}
			case 6: // Err
				ev.Err = string(v)
			}
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return ev
			}
			data = data[n:]
		}
	}
	return ev
}

// decodeJobSummary extracts ID and Name from a clientpb.Job submessage.
func decodeJobSummary(data []byte) (uint32, string) {
	var id uint32
	var name string
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]
		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return id, name
			}
			if num == 1 {
				id = uint32(v)
			}
			data = data[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return id, name
			}
			if num == 2 {
				name = string(v)
			}
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return id, name
			}
			data = data[n:]
		}
	}
	return id, name
}

// ---------------------------------------------------------------------------
// Sessions / Beacons (existing, refactored)
// ---------------------------------------------------------------------------

// SessionInfo holds decoded session data.
type SessionInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	RemoteAddress string `json:"remoteAddress"`
	Transport     string `json:"transport"`
	Username      string `json:"username"`
	Version       string `json:"version"`
}

func decodeSession(data []byte) SessionInfo {
	var s SessionInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return s
			}
			data = data[n:]
			switch num {
			case 1:
				s.ID = string(v)
			case 2:
				s.Name = string(v)
			case 3:
				s.Hostname = string(v)
			case 5:
				s.Username = string(v)
			case 8:
				s.OS = string(v)
			case 9:
				s.Arch = string(v)
			case 10:
				s.Transport = string(v)
			case 11:
				s.RemoteAddress = string(v)
			case 16:
				s.Version = string(v)
			default:
				// skip unknown bytes field
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return s
			}
		}
	}
	return s
}

// decodeSessions decodes a clientpb.Sessions message (field 1 = repeated Session).
func decodeSessions(data []byte) []SessionInfo {
	var sessions []SessionInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			sessions = append(sessions, decodeSession(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return sessions
			}
		}
	}
	return sessions
}

// BeaconInfo holds decoded beacon data.
type BeaconInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	RemoteAddress string `json:"remoteAddress"`
	Transport     string `json:"transport"`
	Username      string `json:"username"`
}

func decodeBeacon(data []byte) BeaconInfo {
	var b BeaconInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return b
			}
			data = data[n:]
			switch num {
			case 1:
				b.ID = string(v)
			case 2:
				b.Name = string(v)
			case 3:
				b.Hostname = string(v)
			case 5:
				b.Username = string(v)
			case 8:
				b.OS = string(v)
			case 9:
				b.Arch = string(v)
			case 10:
				b.Transport = string(v)
			case 11:
				b.RemoteAddress = string(v)
			default:
				// skip unknown bytes field
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return b
			}
		}
	}
	return b
}

// decodeBeacons decodes a clientpb.Beacons message (field 2 = repeated Beacon).
func decodeBeacons(data []byte) []BeaconInfo {
	var beacons []BeaconInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 2 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			beacons = append(beacons, decodeBeacon(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return beacons
			}
		}
	}
	return beacons
}

// ---------------------------------------------------------------------------
// Filesystem: Ls, Cd, Pwd, Mkdir, Rm, Download, Upload
// ---------------------------------------------------------------------------

// encodeLsReq encodes sliverpb.LsReq: Path=1, Request=9
func encodeLsReq(path, sessionID string, timeout int64, isBeacon bool) []byte {
	return encodePathReq(path, sessionID, timeout, isBeacon)
}

// encodeCdReq encodes sliverpb.CdReq: Path=1, Request=9
func encodeCdReq(path, sessionID string, timeout int64, isBeacon bool) []byte {
	return encodePathReq(path, sessionID, timeout, isBeacon)
}

// encodePwdReq encodes sliverpb.PwdReq: Request=9
func encodePwdReq(sessionID string, timeout int64, isBeacon bool) []byte {
	return encodeSimpleReq(sessionID, timeout, isBeacon)
}

// encodeMkdirReq encodes sliverpb.MkdirReq: Path=1, Request=9
func encodeMkdirReq(path, sessionID string, timeout int64, isBeacon bool) []byte {
	return encodePathReq(path, sessionID, timeout, isBeacon)
}

// encodeRmReq encodes sliverpb.RmReq: Path=1, Recursive=2, Force=3, Request=9
func encodeRmReq(path string, recursive, force bool, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, path)
	if recursive {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	if force {
		b = protowire.AppendTag(b, 3, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// encodeDownloadReq encodes sliverpb.DownloadReq: Path=1, Request=9
func encodeDownloadReq(path, sessionID string, timeout int64, isBeacon bool) []byte {
	return encodePathReq(path, sessionID, timeout, isBeacon)
}

// encodeUploadReq encodes sliverpb.UploadReq: Path=1, Encoder=2, Data=3, IsIOC=4, FileName=5, Request=9
func encodeUploadReq(remotePath string, data []byte, encoder string, fileName string, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	// Path=1
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, remotePath)
	// Encoder=2
	if encoder != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, encoder)
	}
	// Data=3
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	b = protowire.AppendBytes(b, data)
	// FileName=5
	if fileName != "" {
		b = protowire.AppendTag(b, 5, protowire.BytesType)
		b = protowire.AppendString(b, fileName)
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// FileInfo holds decoded file metadata from Ls response.
type FileInfo struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"modTime"`
	Mode    string `json:"mode"`
	Link    string `json:"link"`
}

func decodeFileInfo(data []byte) FileInfo {
	var f FileInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return f
			}
			data = data[n:]
			switch num {
			case 1: // Name
				f.Name = string(v)
			case 5: // Mode
				f.Mode = string(v)
			case 6: // Link
				f.Link = string(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return f
			}
			data = data[n:]
			switch num {
			case 2: // IsDir
				f.IsDir = v != 0
			case 3: // Size
				f.Size = int64(v)
			case 4: // ModTime
				f.ModTime = int64(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return f
			}
		}
	}
	return f
}

// LsResult holds decoded Ls response.
type LsResult struct {
	Path   string
	Exists bool
	Files  []FileInfo
	Err    string
}

// decodeLsResp decodes sliverpb.Ls: Path=1, Exists=2, Files=3(repeated), Response=9
func decodeLsResp(data []byte) LsResult {
	var r LsResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Path = string(v)
			case 3:
				r.Files = append(r.Files, decodeFileInfo(v))
			case 9:
				r.Err = decodeResponseErr(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			if num == 2 {
				r.Exists = v != 0
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// PwdResult holds decoded Pwd/Cd response.
type PwdResult struct {
	Path string
	Err  string
}

// decodePwdResp decodes sliverpb.Pwd: Path=1, Response=9
func decodePwdResp(data []byte) PwdResult {
	var r PwdResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Path = string(v)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// MkdirResult holds decoded Mkdir response.
type MkdirResult struct {
	Path string
	Err  string
}

// decodeMkdirResp decodes sliverpb.Mkdir: Path=1, Response=9
func decodeMkdirResp(data []byte) MkdirResult {
	var r MkdirResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Path = string(v)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// RmResult holds decoded Rm response.
type RmResult struct {
	Path string
	Err  string
}

// decodeRmResp decodes sliverpb.Rm: Path=1, Response=9
func decodeRmResp(data []byte) RmResult {
	var r RmResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Path = string(v)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// DownloadResult holds decoded Download response.
type DownloadResult struct {
	Path    string
	Data    []byte // raw (may be gzip)
	Exists  bool
	Encoder string
	Err     string
}

// decodeDownloadResp decodes sliverpb.Download: Path=1, Encoder=2, Exists=3, Data=6, Response=9
func decodeDownloadResp(data []byte) DownloadResult {
	var r DownloadResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1: // Path
				r.Path = string(v)
			case 2: // Encoder
				r.Encoder = string(v)
			case 6: // Data
				r.Data = append([]byte(nil), v...)
			case 9: // Response
				r.Err = decodeResponseErr(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			if num == 3 { // Exists
				r.Exists = v != 0
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// DecompressDownload decompresses gzip data if the encoder field indicates gzip.
func DecompressDownload(dl DownloadResult) ([]byte, error) {
	if dl.Encoder != "gzip" || len(dl.Data) == 0 {
		return dl.Data, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(dl.Data))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()
	return io.ReadAll(gz)
}

// gzipCompress compresses data using gzip.
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UploadResult holds decoded Upload response.
type UploadResult struct {
	Path string
	Err  string
}

// decodeUploadResp decodes sliverpb.Upload: Path=1, Response=9
func decodeUploadResp(data []byte) UploadResult {
	var r UploadResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Path = string(v)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Process: Ps, Terminate
// ---------------------------------------------------------------------------

// encodePsReq encodes sliverpb.PsReq: Request=9
func encodePsReq(sessionID string, timeout int64, isBeacon bool) []byte {
	return encodeSimpleReq(sessionID, timeout, isBeacon)
}

// encodeTerminateReq encodes sliverpb.TerminateReq: Pid=1(varint), Force=2(bool), Request=9
func encodeTerminateReq(pid int32, force bool, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(pid))
	if force {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// encodeProcessDumpReq encodes sliverpb.ProcessDumpReq: Pid=1(varint), Request=9
func encodeProcessDumpReq(pid int32, dumpTimeout int32, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	// Pid=1
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(pid))
	// Timeout=2 (procdump-specific timeout in seconds)
	if dumpTimeout > 0 {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(dumpTimeout))
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// ProcessInfo holds decoded process data.
type ProcessInfo struct {
	Pid        int32  `json:"pid"`
	Ppid       int32  `json:"ppid"`
	Executable string `json:"executable"`
	Owner      string `json:"owner"`
	Arch       string `json:"architecture"`
	SessionID  int32  `json:"sessionID"`
}

func decodeProcess(data []byte) ProcessInfo {
	var p ProcessInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return p
			}
			data = data[n:]
			switch num {
			case 1:
				p.Pid = int32(v)
			case 2:
				p.Ppid = int32(v)
			case 8:
				p.SessionID = int32(v)
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return p
			}
			data = data[n:]
			switch num {
			case 3:
				p.Executable = string(v)
			case 4:
				p.Owner = string(v)
			case 7:
				p.Arch = string(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return p
			}
		}
	}
	return p
}

// PsResult holds decoded Ps response.
type PsResult struct {
	Processes []ProcessInfo
	Err       string
}

// decodePsResp decodes sliverpb.Ps: Processes=1(repeated), Response=9
func decodePsResp(data []byte) PsResult {
	var r PsResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Processes = append(r.Processes, decodeProcess(v))
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// TerminateResult holds decoded Terminate response.
type TerminateResult struct {
	Pid int32
	Err string
}

// decodeTerminateResp decodes sliverpb.Terminate: Pid=1(varint), Response=9
func decodeTerminateResp(data []byte) TerminateResult {
	var r TerminateResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			if num == 1 {
				r.Pid = int32(v)
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			if num == 9 {
				r.Err = decodeResponseErr(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ProcessDumpResult holds decoded ProcessDump response.
type ProcessDumpResult struct {
	Data []byte
	Err  string
}

// decodeProcessDumpResp decodes sliverpb.ProcessDump: Data=1(bytes), Response=9
func decodeProcessDumpResp(data []byte) ProcessDumpResult {
	var r ProcessDumpResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Data = append([]byte(nil), v...)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Network: Ifconfig, Netstat
// ---------------------------------------------------------------------------

// encodeIfconfigReq encodes sliverpb.IfconfigReq: Request=9
func encodeIfconfigReq(sessionID string, timeout int64, isBeacon bool) []byte {
	return encodeSimpleReq(sessionID, timeout, isBeacon)
}

// encodeNetstatReq encodes sliverpb.NetstatReq: TCP=1, UDP=2, IP4=3, IP6=5, Listening=6, Request=9
func encodeNetstatReq(tcp, udp, ip4, ip6, listening bool, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	if tcp {
		b = protowire.AppendTag(b, 1, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	if udp {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	if ip4 {
		b = protowire.AppendTag(b, 3, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	if ip6 {
		b = protowire.AppendTag(b, 5, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	if listening {
		b = protowire.AppendTag(b, 6, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// NetInterface holds decoded network interface data.
type NetInterface struct {
	Index       int32    `json:"index"`
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	IPAddresses []string `json:"ipAddresses"`
	MTU         int32    `json:"mtu"`
}

func decodeNetInterface(data []byte) NetInterface {
	var n NetInterface
	for len(data) > 0 {
		num, typ, tagN := protowire.ConsumeTag(data)
		if tagN < 0 {
			break
		}
		data = data[tagN:]

		switch typ {
		case protowire.VarintType:
			v, vn := protowire.ConsumeVarint(data)
			if vn < 0 {
				return n
			}
			data = data[vn:]
			switch num {
			case 1:
				n.Index = int32(v)
			case 5:
				n.MTU = int32(v)
			}
		case protowire.BytesType:
			v, vn := protowire.ConsumeBytes(data)
			if vn < 0 {
				return n
			}
			data = data[vn:]
			switch num {
			case 2:
				n.Name = string(v)
			case 3:
				n.MAC = string(v)
			case 4:
				n.IPAddresses = append(n.IPAddresses, string(v))
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return n
			}
		}
	}
	return n
}

// IfconfigResult holds decoded Ifconfig response.
type IfconfigResult struct {
	Interfaces []NetInterface
	Err        string
}

// decodeIfconfigResp decodes sliverpb.Ifconfig: NetInterfaces=1(repeated), Response=9
func decodeIfconfigResp(data []byte) IfconfigResult {
	var r IfconfigResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Interfaces = append(r.Interfaces, decodeNetInterface(v))
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// SockTabAddr holds decoded address from netstat.
type SockTabAddr struct {
	IP   string `json:"ip"`
	Port uint32 `json:"port"`
}

func decodeSockTabAddr(data []byte) SockTabAddr {
	var a SockTabAddr
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return a
			}
			data = data[n:]
			if num == 1 {
				a.IP = string(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return a
			}
			data = data[n:]
			if num == 2 {
				a.Port = uint32(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return a
			}
		}
	}
	return a
}

// SockTabEntry holds decoded netstat entry.
type SockTabEntry struct {
	LocalAddr  SockTabAddr `json:"localAddr"`
	RemoteAddr SockTabAddr `json:"remoteAddr"`
	SkState    string      `json:"skState"`
	UID        uint32      `json:"uid"`
	Protocol   string      `json:"protocol"`
	Process    ProcessInfo `json:"process"`
}

func decodeSockTabEntry(data []byte) SockTabEntry {
	var e SockTabEntry
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return e
			}
			data = data[n:]
			switch num {
			case 1:
				e.LocalAddr = decodeSockTabAddr(v)
			case 2:
				e.RemoteAddr = decodeSockTabAddr(v)
			case 3:
				e.SkState = string(v)
			case 6:
				e.Protocol = string(v)
			case 5:
				e.Process = decodeProcess(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return e
			}
			data = data[n:]
			if num == 4 {
				e.UID = uint32(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return e
			}
		}
	}
	return e
}

// NetstatResult holds decoded Netstat response.
type NetstatResult struct {
	Entries []SockTabEntry
	Err     string
}

// decodeNetstatResp decodes sliverpb.Netstat: Entries=1(repeated), Response=9
func decodeNetstatResp(data []byte) NetstatResult {
	var r NetstatResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Entries = append(r.Entries, decodeSockTabEntry(v))
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Recon: Screenshot, CurrentTokenOwner, GetUID, GetGID, GetPrivs, GetEnv
// ---------------------------------------------------------------------------

// encodeScreenshotReq encodes sliverpb.ScreenshotReq: Request=9
func encodeScreenshotReq(sessionID string, timeout int64, isBeacon bool) []byte {
	return encodeSimpleReq(sessionID, timeout, isBeacon)
}

// ScreenshotResult holds decoded Screenshot response.
type ScreenshotResult struct {
	Data []byte
	Err  string
}

// decodeScreenshotResp decodes sliverpb.Screenshot: Data=1(bytes), Response=9
func decodeScreenshotResp(data []byte) ScreenshotResult {
	var r ScreenshotResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Data = append([]byte(nil), v...)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// encodeCurrentTokenOwnerReq encodes sliverpb.CurrentTokenOwnerReq: Request=9
func encodeCurrentTokenOwnerReq(sessionID string, timeout int64, isBeacon bool) []byte {
	return encodeSimpleReq(sessionID, timeout, isBeacon)
}

// CurrentTokenOwnerResult holds decoded response.
type CurrentTokenOwnerResult struct {
	Output string
	Err    string
}

// decodeCurrentTokenOwnerResp decodes: Output=1(string), Response=9
func decodeCurrentTokenOwnerResp(data []byte) CurrentTokenOwnerResult {
	var r CurrentTokenOwnerResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Output = string(v)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// encodeGetPrivsReq encodes sliverpb.GetPrivsReq: Request=9
func encodeGetPrivsReq(sessionID string, timeout int64, isBeacon bool) []byte {
	return encodeSimpleReq(sessionID, timeout, isBeacon)
}

// PrivilegeEntry holds decoded Windows privilege entry.
type PrivilegeEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	EnabledByDefault bool `json:"enabledByDefault"`
	Removed     bool   `json:"removed"`
}

func decodePrivilegeEntry(data []byte) PrivilegeEntry {
	var p PrivilegeEntry
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return p
			}
			data = data[n:]
			switch num {
			case 1:
				p.Name = string(v)
			case 2:
				p.Description = string(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return p
			}
			data = data[n:]
			switch num {
			case 3:
				p.Enabled = v != 0
			case 4:
				p.EnabledByDefault = v != 0
			case 5:
				p.Removed = v != 0
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return p
			}
		}
	}
	return p
}

// GetPrivsResult holds decoded GetPrivs response.
type GetPrivsResult struct {
	PrivInfo         []PrivilegeEntry
	ProcessIntegrity string
	ProcessName      string
	Err              string
}

// decodeGetPrivsResp decodes: PrivInfo=1(repeated), ProcessIntegrity=2(string), ProcessName=3(string), Response=9
func decodeGetPrivsResp(data []byte) GetPrivsResult {
	var r GetPrivsResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.PrivInfo = append(r.PrivInfo, decodePrivilegeEntry(v))
			case 2:
				r.ProcessIntegrity = string(v)
			case 3:
				r.ProcessName = string(v)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// encodeEnvReq encodes sliverpb.EnvReq: Name=1(string), Request=9
func encodeEnvReq(name, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	if name != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, name)
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// EnvEntry holds decoded environment variable.
type EnvEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func decodeEnvEntry(data []byte) EnvEntry {
	var e EnvEntry
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return e
			}
			data = data[n:]
			switch num {
			case 1:
				e.Key = string(v)
			case 2:
				e.Value = string(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return e
			}
		}
	}
	return e
}

// EnvResult holds decoded EnvInfo response.
type EnvResult struct {
	Variables []EnvEntry
	Err       string
}

// decodeEnvResp decodes sliverpb.EnvInfo: Variables=1(repeated), Response=9
func decodeEnvResp(data []byte) EnvResult {
	var r EnvResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Variables = append(r.Variables, decodeEnvEntry(v))
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Execution: ExecuteAssembly, Sideload
// ---------------------------------------------------------------------------

// encodeExecuteAssemblyReq encodes sliverpb.ExecuteAssemblyReq:
// Assembly=1(bytes), Arguments=2(string), Process=3(string), IsDLL=4(bool),
// Arch=5(string), ClassName=6(string), Method=7(string), AppDomain=8(string), Request=9
func encodeExecuteAssemblyReq(assembly []byte, arguments, process string, isDLL bool, arch, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, assembly)
	if arguments != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, arguments)
	}
	if process != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, process)
	}
	if isDLL {
		b = protowire.AppendTag(b, 4, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	if arch != "" {
		b = protowire.AppendTag(b, 5, protowire.BytesType)
		b = protowire.AppendString(b, arch)
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// ExecuteAssemblyResult holds decoded response.
type ExecuteAssemblyResult struct {
	Output []byte
	Err    string
}

// decodeExecuteAssemblyResp decodes: Output=1(bytes), Response=9
func decodeExecuteAssemblyResp(data []byte) ExecuteAssemblyResult {
	var r ExecuteAssemblyResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Output = append([]byte(nil), v...)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// encodeSideloadReq encodes sliverpb.SideloadReq:
// Data=1(bytes), ProcessName=2(string), Args=3(string), EntryPoint=4(string), Request=9
func encodeSideloadReq(data []byte, processName, args, entryPoint, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, data)
	if processName != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, processName)
	}
	if args != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, args)
	}
	if entryPoint != "" {
		b = protowire.AppendTag(b, 4, protowire.BytesType)
		b = protowire.AppendString(b, entryPoint)
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// SideloadResult holds decoded response.
type SideloadResult struct {
	Result string
	Err    string
}

// decodeSideloadResp decodes: Result=1(string), Response=9
func decodeSideloadResp(data []byte) SideloadResult {
	var r SideloadResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.Result = string(v)
			case 9:
				r.Err = decodeResponseErr(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Session management: Kill
// ---------------------------------------------------------------------------

// encodeKillReq encodes sliverpb.KillReq: Force=1(bool), Request=9
func encodeKillReq(force bool, sessionID string, timeout int64, isBeacon bool) []byte {
	var b []byte
	if force {
		b = protowire.AppendTag(b, 1, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	return appendRequestField(b, sessionID, timeout, isBeacon)
}

// ---------------------------------------------------------------------------
// Server-level: Jobs, Listeners, Operators, Version
// ---------------------------------------------------------------------------

// JobInfo holds decoded job data.
type JobInfo struct {
	ID          uint32 `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
	Port        uint32 `json:"port"`
}

func decodeJob(data []byte) JobInfo {
	var j JobInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return j
			}
			data = data[n:]
			switch num {
			case 1:
				j.ID = uint32(v)
			case 5:
				j.Port = uint32(v)
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return j
			}
			data = data[n:]
			switch num {
			case 2:
				j.Name = string(v)
			case 3:
				j.Description = string(v)
			case 4:
				j.Protocol = string(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return j
			}
		}
	}
	return j
}

// decodeJobsResp decodes clientpb.Jobs: Active=1(repeated Job)
func decodeJobsResp(data []byte) []JobInfo {
	var jobs []JobInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			jobs = append(jobs, decodeJob(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return jobs
			}
		}
	}
	return jobs
}

// encodeKillJobReq encodes clientpb.KillJobReq: ID=1(uint32)
func encodeKillJobReq(id uint32) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(id))
	return b
}

// KillJobResult holds decoded KillJob response.
type KillJobResult struct {
	ID      uint32
	Success bool
}

// decodeKillJobResp decodes clientpb.KillJob: ID=1(varint), Success=2(bool)
func decodeKillJobResp(data []byte) KillJobResult {
	var r KillJobResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.VarintType {
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch num {
			case 1:
				r.ID = uint32(v)
			case 2:
				r.Success = v != 0
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ListenerJobResult holds decoded ListenerJob response.
type ListenerJobResult struct {
	JobID uint32
	Err   string
}

// decodeListenerJobResp decodes clientpb.ListenerJob: ID=1(string), Type=2(string), JobID=3(varint)
func decodeListenerJobResp(data []byte) ListenerJobResult {
	var r ListenerJobResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			if num == 3 { // JobID
				r.JobID = uint32(v)
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			_ = v
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// encodeMTLSListenerReq encodes clientpb.MTLSListenerReq: Host=1, Port=2, Persistent=3
func encodeMTLSListenerReq(host string, port uint32) []byte {
	var b []byte
	if host != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, host)
	}
	if port > 0 {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(port))
	}
	return b
}

// encodeHTTPListenerReq encodes clientpb.HTTPListenerReq: Domain=1, Host=2, Port=3, Secure=4, Website=5, Persistent=10
func encodeHTTPListenerReq(domain, host string, port uint32, secure bool) []byte {
	var b []byte
	if domain != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, domain)
	}
	if host != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, host)
	}
	if port > 0 {
		b = protowire.AppendTag(b, 3, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(port))
	}
	if secure {
		b = protowire.AppendTag(b, 4, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	return b
}

// encodeDNSListenerReq encodes clientpb.DNSListenerReq: Domains=1(repeated), Canaries=2, Host=3, Port=4, Persistent=6
func encodeDNSListenerReq(domains []string, canaries bool, host string, port uint32) []byte {
	var b []byte
	for _, d := range domains {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, d)
	}
	if canaries {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
	}
	if host != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, host)
	}
	if port > 0 {
		b = protowire.AppendTag(b, 4, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(port))
	}
	return b
}

// encodeWGListenerReq encodes clientpb.WGListenerReq: Host=6, Port=1, TunIP=2, NPort=3, KeyPort=4, Persistent=5
func encodeWGListenerReq(host string, port uint32) []byte {
	var b []byte
	if port > 0 {
		b = protowire.AppendTag(b, 1, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(port))
	}
	if host != "" {
		b = protowire.AppendTag(b, 6, protowire.BytesType)
		b = protowire.AppendString(b, host)
	}
	return b
}

// OperatorInfo holds decoded operator data.
type OperatorInfo struct {
	Online bool   `json:"online"`
	Name   string `json:"name"`
}

func decodeOperator(data []byte) OperatorInfo {
	var o OperatorInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return o
			}
			data = data[n:]
			if num == 1 {
				o.Online = v != 0
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return o
			}
			data = data[n:]
			if num == 2 {
				o.Name = string(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return o
			}
		}
	}
	return o
}

// decodeOperatorsResp decodes clientpb.Operators: Operators=1(repeated)
func decodeOperatorsResp(data []byte) []OperatorInfo {
	var ops []OperatorInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			ops = append(ops, decodeOperator(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return ops
			}
		}
	}
	return ops
}

// VersionInfo holds decoded server version.
type VersionInfo struct {
	Major      int32  `json:"major"`
	Minor      int32  `json:"minor"`
	Patch      int32  `json:"patch"`
	Commit     string `json:"commit"`
	Dirty      bool   `json:"dirty"`
	CompiledAt int64  `json:"compiledAt"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
}

// decodeVersionResp decodes clientpb.Version
func decodeVersionResp(data []byte) VersionInfo {
	var v VersionInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			val, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return v
			}
			data = data[n:]
			switch num {
			case 1:
				v.Major = int32(val)
			case 2:
				v.Minor = int32(val)
			case 3:
				v.Patch = int32(val)
			case 5:
				v.Dirty = val != 0
			case 6:
				v.CompiledAt = int64(val)
			}
		case protowire.BytesType:
			val, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return v
			}
			data = data[n:]
			switch num {
			case 4:
				v.Commit = string(val)
			case 7:
				v.OS = string(val)
			case 8:
				v.Arch = string(val)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return v
			}
		}
	}
	return v
}

// ---------------------------------------------------------------------------
// Server-level: ImplantBuilds, ImplantProfiles, Hosts, Loot, Websites,
//               Canaries, Builders, Generate
// ---------------------------------------------------------------------------

// ImplantBuildInfo holds decoded implant build data.
type ImplantBuildInfo struct {
	Name string `json:"name"`
	// ImplantConfig is complex; we extract key summary fields
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Format string `json:"format"`
}

// decodeImplantConfig extracts summary fields from clientpb.ImplantConfig submessage.
func decodeImplantConfig(data []byte) (os, arch, format string) {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return
			}
			data = data[n:]
			if num == 100 { // OutputFormat enum
				switch v {
				case 0:
					format = "SHARED_LIB"
				case 1:
					format = "SHELLCODE"
				case 2:
					format = "EXECUTABLE"
				case 3:
					format = "SERVICE"
				}
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return
			}
			data = data[n:]
			switch num {
			case 7: // GOOS
				os = string(v)
			case 8: // GOARCH
				arch = string(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return
			}
		}
	}
	return
}

// decodeImplantBuildsResp decodes clientpb.ImplantBuilds: Configs=1(map<string, ImplantConfig>)
// The map is encoded as repeated field 1, each entry is a submessage with key=1(string), value=2(submsg)
func decodeImplantBuildsResp(data []byte) []ImplantBuildInfo {
	var builds []ImplantBuildInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			// Decode map entry: key=1(string), value=2(bytes/submsg)
			var name string
			var configData []byte
			inner := v
			for len(inner) > 0 {
				inum, ityp, in := protowire.ConsumeTag(inner)
				if in < 0 {
					break
				}
				inner = inner[in:]
				if ityp == protowire.BytesType {
					iv, in := protowire.ConsumeBytes(inner)
					if in < 0 {
						break
					}
					inner = inner[in:]
					switch inum {
					case 1:
						name = string(iv)
					case 2:
						configData = iv
					}
				} else {
					var ok bool
					inner, ok = skipField(inner, ityp)
					if !ok {
						break
					}
				}
			}
			os, arch, format := decodeImplantConfig(configData)
			builds = append(builds, ImplantBuildInfo{
				Name:   name,
				OS:     os,
				Arch:   arch,
				Format: format,
			})
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return builds
			}
		}
	}
	return builds
}

// ImplantProfileInfo holds decoded implant profile.
type ImplantProfileInfo struct {
	Name string `json:"name"`
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// decodeImplantProfilesResp decodes clientpb.ImplantProfiles: Profiles=1(repeated ImplantProfile)
// ImplantProfile: Name=1(string), Config=2(ImplantConfig submsg)
func decodeImplantProfilesResp(data []byte) []ImplantProfileInfo {
	var profiles []ImplantProfileInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			var p ImplantProfileInfo
			inner := v
			for len(inner) > 0 {
				inum, ityp, in := protowire.ConsumeTag(inner)
				if in < 0 {
					break
				}
				inner = inner[in:]
				if ityp == protowire.BytesType {
					iv, in := protowire.ConsumeBytes(inner)
					if in < 0 {
						break
					}
					inner = inner[in:]
					switch inum {
					case 1:
						p.Name = string(iv)
					case 2:
						p.OS, p.Arch, _ = decodeImplantConfig(iv)
					}
				} else {
					var ok bool
					inner, ok = skipField(inner, ityp)
					if !ok {
						break
					}
				}
			}
			profiles = append(profiles, p)
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return profiles
			}
		}
	}
	return profiles
}

// HostInfo holds decoded host data.
type HostInfo struct {
	ID       uint32 `json:"id"`
	Hostname string `json:"hostname"`
	OSVersion string `json:"osVersion"`
}

// decodeHost decodes clientpb.Host: ID=1(varint), Hostname=2(string), OSVersion=5(string)
func decodeHost(data []byte) HostInfo {
	var h HostInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return h
			}
			data = data[n:]
			if num == 1 {
				h.ID = uint32(v)
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return h
			}
			data = data[n:]
			switch num {
			case 2:
				h.Hostname = string(v)
			case 5:
				h.OSVersion = string(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return h
			}
		}
	}
	return h
}

// decodeHostsResp decodes clientpb.AllHosts: Hosts=1(repeated)
func decodeHostsResp(data []byte) []HostInfo {
	var hosts []HostInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			hosts = append(hosts, decodeHost(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return hosts
			}
		}
	}
	return hosts
}

// LootInfo holds decoded loot entry.
type LootInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     int32  `json:"type"`
	CredType int32  `json:"credType"`
}

// decodeLoot decodes clientpb.Loot: ID=1(string), Name=2(string), Type=3(enum/varint), CredentialType=4(enum/varint)
func decodeLoot(data []byte) LootInfo {
	var l LootInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return l
			}
			data = data[n:]
			switch num {
			case 1:
				l.ID = string(v)
			case 2:
				l.Name = string(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return l
			}
			data = data[n:]
			switch num {
			case 3:
				l.Type = int32(v)
			case 4:
				l.CredType = int32(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return l
			}
		}
	}
	return l
}

// decodeLootAllResp decodes clientpb.AllLoot: Loot=1(repeated)
func decodeLootAllResp(data []byte) []LootInfo {
	var loot []LootInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			loot = append(loot, decodeLoot(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return loot
			}
		}
	}
	return loot
}

// WebsiteInfo holds decoded website data.
type WebsiteInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// decodeWebsite decodes clientpb.Website: ID=1(string), Name=2(string)
func decodeWebsite(data []byte) WebsiteInfo {
	var w WebsiteInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return w
			}
			data = data[n:]
			switch num {
			case 1:
				w.ID = string(v)
			case 2:
				w.Name = string(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return w
			}
		}
	}
	return w
}

// decodeWebsitesResp decodes clientpb.Websites: Websites=1(repeated)
func decodeWebsitesResp(data []byte) []WebsiteInfo {
	var sites []WebsiteInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			sites = append(sites, decodeWebsite(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return sites
			}
		}
	}
	return sites
}

// CanaryInfo holds decoded canary data.
type CanaryInfo struct {
	ID              string `json:"id"`
	ImplantName     string `json:"implantName"`
	Domain          string `json:"domain"`
	Triggered       bool   `json:"triggered"`
	FirstTriggered  string `json:"firstTriggered"`
	LatestTrigger   string `json:"latestTrigger"`
}

// decodeCanary decodes clientpb.DNSCanary
func decodeCanary(data []byte) CanaryInfo {
	var c CanaryInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return c
			}
			data = data[n:]
			switch num {
			case 1:
				c.ID = string(v)
			case 2:
				c.ImplantName = string(v)
			case 3:
				c.Domain = string(v)
			case 5:
				c.FirstTriggered = string(v)
			case 6:
				c.LatestTrigger = string(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return c
			}
			data = data[n:]
			if num == 4 {
				c.Triggered = v != 0
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return c
			}
		}
	}
	return c
}

// decodeCanariesResp decodes clientpb.Canaries: Canaries=1(repeated)
func decodeCanariesResp(data []byte) []CanaryInfo {
	var canaries []CanaryInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			canaries = append(canaries, decodeCanary(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return canaries
			}
		}
	}
	return canaries
}

// BuilderInfo holds decoded external builder data.
type BuilderInfo struct {
	Name     string `json:"name"`
	Operator string `json:"operator"`
	GOOS     string `json:"goos"`
	GOARCH   string `json:"goarch"`
}

// decodeBuilder decodes clientpb.Builder
func decodeBuilder(data []byte) BuilderInfo {
	var b BuilderInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return b
			}
			data = data[n:]
			switch num {
			case 1:
				b.Name = string(v)
			case 2:
				b.Operator = string(v)
			case 3:
				b.GOOS = string(v)
			case 4:
				b.GOARCH = string(v)
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return b
			}
		}
	}
	return b
}

// decodeBuildersResp decodes clientpb.Builders: Builders=1(repeated)
func decodeBuildersResp(data []byte) []BuilderInfo {
	var builders []BuilderInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			builders = append(builders, decodeBuilder(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return builders
			}
		}
	}
	return builders
}

// ---------------------------------------------------------------------------
// Generate (implant generation)
// ---------------------------------------------------------------------------

// encodeGenerateReq encodes clientpb.GenerateReq: Config=1(ImplantConfig submsg)
// This is a simplified encoder covering the most common generation options.
func encodeGenerateReq(config ImplantGenerateConfig) []byte {
	// Encode the ImplantConfig submessage
	var cfg []byte

	// IsBeacon=4(bool)
	if config.IsBeacon {
		cfg = protowire.AppendTag(cfg, 4, protowire.VarintType)
		cfg = protowire.AppendVarint(cfg, 1)
	}

	// GOOS=7(string)
	if config.GOOS != "" {
		cfg = protowire.AppendTag(cfg, 7, protowire.BytesType)
		cfg = protowire.AppendString(cfg, config.GOOS)
	}
	// GOARCH=8(string)
	if config.GOARCH != "" {
		cfg = protowire.AppendTag(cfg, 8, protowire.BytesType)
		cfg = protowire.AppendString(cfg, config.GOARCH)
	}

	// C2 repeated field 50 = ImplantC2 submessage
	for _, c2 := range config.C2 {
		var c2msg []byte
		// Priority=2(varint)
		c2msg = protowire.AppendTag(c2msg, 2, protowire.VarintType)
		c2msg = protowire.AppendVarint(c2msg, uint64(c2.Priority))
		// URL=3(string)
		c2msg = protowire.AppendTag(c2msg, 3, protowire.BytesType)
		c2msg = protowire.AppendString(c2msg, c2.URL)
		cfg = protowire.AppendTag(cfg, 50, protowire.BytesType)
		cfg = protowire.AppendBytes(cfg, c2msg)
	}

	// OutputFormat=100(varint/enum)
	if config.Format > 0 {
		cfg = protowire.AppendTag(cfg, 100, protowire.VarintType)
		cfg = protowire.AppendVarint(cfg, uint64(config.Format))
	}

	// HTTPC2ConfigName=150(string) — required by server even for non-HTTP C2
	httpc2Name := config.HTTPC2ConfigName
	if httpc2Name == "" {
		httpc2Name = "default"
	}
	cfg = protowire.AppendTag(cfg, 150, protowire.BytesType)
	cfg = protowire.AppendString(cfg, httpc2Name)

	// Encode outer GenerateReq message
	var b []byte
	// Config=1(ImplantConfig submsg)
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, cfg)
	// Name=2(string) — on GenerateReq, not ImplantConfig
	if config.Name != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, config.Name)
	}
	return b
}

// ImplantC2Config represents a C2 endpoint for generation.
type ImplantC2Config struct {
	Priority uint32 `json:"priority"`
	URL      string `json:"url"`
}

// ImplantGenerateConfig holds generation parameters.
type ImplantGenerateConfig struct {
	IsBeacon         bool              `json:"isBeacon"`
	C2               []ImplantC2Config `json:"c2"`
	GOOS             string            `json:"goos"`
	GOARCH           string            `json:"goarch"`
	Name             string            `json:"name"`
	Format           uint32            `json:"format"`           // 0=SHARED_LIB, 1=SHELLCODE, 2=EXECUTABLE, 3=SERVICE
	HTTPC2ConfigName string            `json:"httpc2ConfigName"` // defaults to "default" if empty
}

// GenerateResult holds decoded Generate response.
type GenerateResult struct {
	Data []byte // The implant binary
	Err  string
}

// decodeGenerateResp decodes clientpb.Generate: File=1(clientpb.File submsg)
// File: Name=1(string), Data=2(bytes)
func decodeGenerateResp(data []byte) GenerateResult {
	var r GenerateResult
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			// Decode File submessage - extract Data at field 2
			inner := v
			for len(inner) > 0 {
				inum, ityp, in := protowire.ConsumeTag(inner)
				if in < 0 {
					break
				}
				inner = inner[in:]
				if ityp == protowire.BytesType && inum == 2 {
					iv, in := protowire.ConsumeBytes(inner)
					if in < 0 {
						break
					}
					inner = inner[in:]
					r.Data = append([]byte(nil), iv...)
				} else {
					var ok bool
					inner, ok = skipField(inner, ityp)
					if !ok {
						break
					}
				}
			}
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return r
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Beacon Tasks
// ---------------------------------------------------------------------------

// encodeBeaconTasksReq encodes a request to get beacon tasks.
// clientpb.Beacon: ID=1(string)
func encodeBeaconTasksReq(beaconID string) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, beaconID)
	return b
}

// BeaconTaskInfo holds decoded beacon task.
type BeaconTaskInfo struct {
	ID          string `json:"id"`
	BeaconID    string `json:"beaconId"`
	CreatedAt   int64  `json:"createdAt"`
	State       string `json:"state"`
	SentAt      int64  `json:"sentAt"`
	CompletedAt int64  `json:"completedAt"`
	Description string `json:"description"`
}

func decodeBeaconTask(data []byte) BeaconTaskInfo {
	var t BeaconTaskInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return t
			}
			data = data[n:]
			switch num {
			case 1: // ID
				t.ID = string(v)
			case 2: // BeaconID
				t.BeaconID = string(v)
			case 4: // State
				t.State = string(v)
			case 9: // Description
				t.Description = string(v)
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return t
			}
			data = data[n:]
			switch num {
			case 3: // CreatedAt
				t.CreatedAt = int64(v)
			case 5: // SentAt
				t.SentAt = int64(v)
			case 6: // CompletedAt
				t.CompletedAt = int64(v)
			}
		default:
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return t
			}
		}
	}
	return t
}

// decodeBeaconTasksResp decodes clientpb.BeaconTasks: Tasks=1(repeated)
func decodeBeaconTasksResp(data []byte) []BeaconTaskInfo {
	var tasks []BeaconTaskInfo
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		if typ == protowire.BytesType && num == 1 {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				break
			}
			data = data[n:]
			tasks = append(tasks, decodeBeaconTask(v))
		} else {
			var ok bool
			data, ok = skipField(data, typ)
			if !ok {
				return tasks
			}
		}
	}
	return tasks
}
