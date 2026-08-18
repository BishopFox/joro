package jsautomation

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/BishopFox/joro/internal/jsruntime"
)

// joro.storage: a small key/value store per installed automation, so a triggered script
// can remember what it has already seen.
//
// In memory, serialized into the project config on save, and reset when the project
// changes — the same lifecycle as plugin project state, for the same reason. "IDs I have
// already tested" is a fact about one engagement, and an automation that carried it into
// the next one would confidently skip a client it has never touched.
//
// Not a capability. There is no argument to authorize: the namespace is bound from the
// automation's own identity by namespaced(), never taken from the script, and storage
// reaches nothing outside itself. See jsruntime.StorageBridge.

// Bounds. Fixed rather than operator-configurable: this is a scratchpad for bookkeeping,
// and an automation that needs more than this wants a finding or a note, which are
// capabilities with their own budgets and which the operator can actually see.
const (
	maxStorageKeys       = 200
	maxStorageKeyLen     = 128
	maxStorageValueBytes = 64 << 10
	maxStorageTotalBytes = 256 << 10
)

// Storage holds every automation's namespace.
type Storage struct {
	mu sync.Mutex
	ns map[string]map[string]json.RawMessage
	// rev increments on every mutation. The autosave loop compares a signature rather
	// than diffing state, and an opaque blob's byte count can change without its
	// length changing, so a counter is the only honest way to report "this is dirty".
	rev atomic.Uint64
}

// NewStorage returns an empty store.
func NewStorage() *Storage {
	return &Storage{ns: make(map[string]map[string]json.RawMessage)}
}

// Revision reports the mutation counter, for the autosave dirty check.
func (s *Storage) Revision() uint64 { return s.rev.Load() }

func storageErr(code, format string, args ...any) error {
	return &jsruntime.CallError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Op applies one operation within a namespace. Errors are CallErrors so the script sees a
// code it can branch on.
func (s *Storage) Op(id, op, key string, value json.RawMessage) (json.RawMessage, error) {
	if id == "" {
		return nil, storageErr("storage_unavailable", "%s", "this run has no storage namespace")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch op {
	case "keys":
		bucket := s.ns[id]
		keys := make([]string, 0, len(bucket))
		for k := range bucket {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return json.Marshal(keys)

	case "get":
		if err := checkKey(key); err != nil {
			return nil, err
		}
		if v, ok := s.ns[id][key]; ok {
			return v, nil
		}
		// Absent reads as null rather than an error: "have I seen this?" is the
		// commonest thing a script asks, and making it throw would push every author
		// into a try/catch around a normal answer.
		return json.RawMessage("null"), nil

	case "delete":
		if err := checkKey(key); err != nil {
			return nil, err
		}
		bucket := s.ns[id]
		_, existed := bucket[key]
		if existed {
			delete(bucket, key)
			if len(bucket) == 0 {
				delete(s.ns, id)
			}
			s.rev.Add(1)
		}
		return json.Marshal(existed)

	case "set":
		if err := checkKey(key); err != nil {
			return nil, err
		}
		if len(value) > maxStorageValueBytes {
			return nil, storageErr("storage_too_large",
				"value is %d bytes, over the %d byte limit for one key", len(value), maxStorageValueBytes)
		}
		bucket := s.ns[id]
		if bucket == nil {
			bucket = make(map[string]json.RawMessage)
			s.ns[id] = bucket
		}
		if _, replacing := bucket[key]; !replacing && len(bucket) >= maxStorageKeys {
			return nil, storageErr("storage_full",
				"this automation already holds %d keys, the limit. Delete one, or keep a single "+
					"aggregate value instead of one key per item", maxStorageKeys)
		}
		// Total is measured against what the namespace would become, not what it is,
		// so a single oversize write cannot slip through under the wire.
		if total := bucketBytes(bucket) - len(bucket[key]) + len(value) + len(key); total > maxStorageTotalBytes {
			return nil, storageErr("storage_full",
				"this write would take the automation to %d bytes, over its %d byte limit",
				total, maxStorageTotalBytes)
		}
		stored := make(json.RawMessage, len(value))
		copy(stored, value)
		bucket[key] = stored
		s.rev.Add(1)
		return json.RawMessage("null"), nil
	}

	return nil, storageErr("invalid_args", "unknown storage operation %q", op)
}

func checkKey(key string) error {
	switch {
	case key == "":
		return storageErr("invalid_args", "%s", "a storage key is required")
	case len(key) > maxStorageKeyLen:
		return storageErr("invalid_args", "key is %d characters, over the %d limit",
			len(key), maxStorageKeyLen)
	}
	return nil
}

func bucketBytes(bucket map[string]json.RawMessage) int {
	n := 0
	for k, v := range bucket {
		n += len(k) + len(v)
	}
	return n
}

// Drop removes an automation's namespace, called when it is uninstalled. Its data has no
// meaning without the code that wrote it.
func (s *Storage) Drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ns[id]; ok {
		delete(s.ns, id)
		s.rev.Add(1)
	}
}

// Reset empties every namespace, on a project switch or a new project.
func (s *Storage) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ns) > 0 {
		clear(s.ns)
		s.rev.Add(1)
	}
}

// Export serializes each namespace for the project config: automation id -> JSON object.
//
// Plain JSON rather than compressed, because the whole project config is gzipped on the
// way to disk and compressing twice buys nothing. The shape matches plugin state
// (name -> opaque bytes) so it can reuse encodePluginStates and its ghost-preservation
// machinery verbatim.
func (s *Storage) Export() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.ns) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(s.ns))
	for id, bucket := range s.ns {
		if len(bucket) == 0 {
			continue
		}
		b, err := json.Marshal(bucket)
		if err != nil {
			continue
		}
		out[id] = b
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Apply replaces every namespace from a project config. Unparseable entries are skipped
// rather than failing the load, following decodePluginStates: one corrupt blob must not
// stop a project from opening.
//
// It returns the ids it could not match to an installed automation, so the caller can
// preserve those blobs across a load-then-save round trip. A teammate's project may
// reference an automation this machine does not have, and dropping the data would mean
// the operator who does have it loses their bookkeeping the first time someone else
// saves the project.
func (s *Storage) Apply(states map[string][]byte, installed func(id string) bool) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	clear(s.ns)
	var unknown []string
	for id, raw := range states {
		if installed != nil && !installed(id) {
			unknown = append(unknown, id)
			continue
		}
		var bucket map[string]json.RawMessage
		if err := json.Unmarshal(raw, &bucket); err != nil || len(bucket) == 0 {
			continue
		}
		// Re-apply every bound Op enforces. A project config is an imported artifact —
		// a teammate publishes one and the operator loads it — so this is an untrusted
		// write path into state an automation trusts, and the ceilings that bound the
		// script's own writes have to bound this one too. Violators are dropped rather
		// than failing the load, matching the skip-and-continue above.
		clean := make(map[string]json.RawMessage, len(bucket))
		total := 0
		for k, v := range bucket {
			if checkKey(k) != nil || len(v) > maxStorageValueBytes || len(clean) >= maxStorageKeys {
				continue
			}
			if total+len(k)+len(v) > maxStorageTotalBytes {
				continue
			}
			total += len(k) + len(v)
			clean[k] = v
		}
		if len(clean) == 0 {
			continue
		}
		s.ns[id] = clean
	}
	s.rev.Add(1)
	sort.Strings(unknown)
	return unknown
}

// namespaced binds a storage handle to one automation, which is what makes the namespace
// un-forgeable: the script never names it, so there is nothing for it to name wrongly.
type namespaced struct {
	s  *Storage
	id string
}

func (n namespaced) Storage(_ context.Context, op, key string, value json.RawMessage) (json.RawMessage, error) {
	return n.s.Op(n.id, op, key, value)
}
