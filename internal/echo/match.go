package echo

// Aho-Corasick over the needle set, so one pass over a view finds every value
// at once. The alternative — a substring search per needle — costs needles x
// bytes, which a request carrying hundreds of parameters turns into hundreds of
// megabytes of scanning per response. Here the cost is the length of the view
// plus the matches, whatever the parameter count.
//
// The root's transitions are a dense array and every other node's a map,
// because almost every byte of a response fails at the root and nowhere else.

// maxNeedleBytes bounds the automaton. Needles are admitted longest-first until
// the budget is spent, so a request that blows the budget loses its least
// distinctive values rather than an arbitrary suffix of them.
const maxNeedleBytes = 64 << 10

type acNode struct {
	next map[byte]int32
	fail int32
	// term is the index of the needle ending at this node, or -1.
	term int32
	// outLink is the nearest node reachable by fail links that is terminal, or
	// -1: it turns reporting every match at a position into a short walk rather
	// than a full fail-chain traversal.
	outLink int32
}

type matcher struct {
	root    [256]int32
	nodes   []acNode
	needles []string
}

// newMatcher builds the automaton. Returns nil when nothing was admitted, which
// callers treat as "no work to do" rather than an error.
func newMatcher(needles []string) *matcher {
	if len(needles) == 0 {
		return nil
	}
	m := &matcher{}
	// Node 0 is the root.
	m.nodes = append(m.nodes, acNode{fail: 0, term: -1, outLink: -1})

	budget := maxNeedleBytes
	for _, n := range needles {
		if len(n) == 0 || len(n) > budget {
			continue
		}
		budget -= len(n)
		idx := int32(len(m.needles))
		m.needles = append(m.needles, n)
		m.insert(n, idx)
	}
	if len(m.needles) == 0 {
		return nil
	}
	m.build()
	return m
}

func (m *matcher) insert(s string, idx int32) {
	cur := int32(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		var nxt int32
		if cur == 0 {
			nxt = m.root[c]
		} else if m.nodes[cur].next != nil {
			nxt = m.nodes[cur].next[c]
		}
		if nxt == 0 {
			m.nodes = append(m.nodes, acNode{fail: 0, term: -1, outLink: -1})
			nxt = int32(len(m.nodes) - 1)
			if cur == 0 {
				m.root[c] = nxt
			} else {
				if m.nodes[cur].next == nil {
					m.nodes[cur].next = make(map[byte]int32, 2)
				}
				m.nodes[cur].next[c] = nxt
			}
		}
		cur = nxt
	}
	// A duplicate needle keeps the first index; callers dedupe before building.
	if m.nodes[cur].term < 0 {
		m.nodes[cur].term = idx
	}
}

// build wires the fail and output links by breadth-first traversal.
func (m *matcher) build() {
	queue := make([]int32, 0, len(m.nodes))
	for c := 0; c < 256; c++ {
		if n := m.root[c]; n != 0 {
			m.nodes[n].fail = 0
			queue = append(queue, n)
		}
	}
	for i := 0; i < len(queue); i++ {
		cur := queue[i]
		for c, nxt := range m.nodes[cur].next {
			f := m.nodes[cur].fail
			for {
				if g := m.goto_(f, c); g != 0 {
					m.nodes[nxt].fail = g
					break
				}
				if f == 0 {
					m.nodes[nxt].fail = 0
					break
				}
				f = m.nodes[f].fail
			}
			queue = append(queue, nxt)
		}
		f := m.nodes[cur].fail
		if m.nodes[f].term >= 0 {
			m.nodes[cur].outLink = f
		} else {
			m.nodes[cur].outLink = m.nodes[f].outLink
		}
	}
}

// goto_ follows one labelled edge without applying fail links.
func (m *matcher) goto_(node int32, c byte) int32 {
	if node == 0 {
		return m.root[c]
	}
	if m.nodes[node].next == nil {
		return 0
	}
	return m.nodes[node].next[c]
}

// find reports every needle occurrence in hay. fn receives the needle's index
// and the half-open range it occupies; returning false stops the scan, which is
// how a per-message reflection cap is enforced without scanning the rest of a
// body whose results are already discarded.
func (m *matcher) find(hay []byte, fn func(idx int32, start, end int) bool) {
	cur := int32(0)
	for i := 0; i < len(hay); i++ {
		c := hay[i]
		for {
			if g := m.goto_(cur, c); g != 0 {
				cur = g
				break
			}
			if cur == 0 {
				break
			}
			cur = m.nodes[cur].fail
		}
		for n := cur; n >= 0; {
			if t := m.nodes[n].term; t >= 0 {
				l := len(m.needles[t])
				if !fn(t, i+1-l, i+1) {
					return
				}
			}
			n = m.nodes[n].outLink
		}
	}
}
