package proxy

import "testing"

func TestParseStatusFilter(t *testing.T) {
	// codes lists status codes the expression must match; reject lists ones it
	// must not. A code of 0 stands for "no response captured".
	tests := []struct {
		expr   string
		match  []int
		reject []int
	}{
		{expr: "", match: []int{0, 200, 404, 500}},
		{expr: "   ", match: []int{0, 200, 404}},
		{expr: "200", match: []int{200}, reject: []int{0, 201, 404}},
		{expr: "4xx", match: []int{400, 403, 499}, reject: []int{0, 302, 500}},
		{expr: "1xx,2xx", match: []int{100, 200, 204}, reject: []int{0, 302, 404}},
		{expr: "500-599", match: []int{500, 502, 599}, reject: []int{0, 499, 600}},
		{expr: "none", match: []int{0}, reject: []int{200, 404}},
		{expr: "0", match: []int{0}, reject: []int{200}},
		{expr: "4xx,5xx,403,500-599", match: []int{403, 404, 500, 599}, reject: []int{0, 200, 302}},
		{expr: " 4xx , 403 ", match: []int{403, 404}, reject: []int{0, 200}},
		{expr: "2xx,none", match: []int{0, 200}, reject: []int{404}},
		// Unparsable expressions fall back to "no filter".
		{expr: "abc", match: []int{0, 200, 404}},
		{expr: "5-", match: []int{0, 200, 404}},
		{expr: "-", match: []int{0, 200, 404}},
		{expr: "600-500", match: []int{0, 200, 404}},
		{expr: "6xx", match: []int{0, 200, 404}},
		// A bad token is skipped, the good one still applies.
		{expr: "abc,404", match: []int{404}, reject: []int{0, 200}},
	}

	for _, tt := range tests {
		sm := parseStatusFilter(tt.expr)
		for _, code := range tt.match {
			if !sm.match(code) {
				t.Errorf("parseStatusFilter(%q).match(%d) = false, want true", tt.expr, code)
			}
		}
		for _, code := range tt.reject {
			if sm.match(code) {
				t.Errorf("parseStatusFilter(%q).match(%d) = true, want false", tt.expr, code)
			}
		}
	}
}

func TestRequestMatcherMethodSet(t *testing.T) {
	m := newRequestMatcher(RequestFilter{Method: "get, POST"})

	for _, method := range []string{"GET", "get", "POST"} {
		if !m.match(&CapturedRequest{Method: method, URL: "http://x/"}) {
			t.Errorf("method %q should match filter %q", method, "get, POST")
		}
	}
	for _, method := range []string{"PUT", "DELETE", "GE"} {
		if m.match(&CapturedRequest{Method: method, URL: "http://x/"}) {
			t.Errorf("method %q should not match filter %q", method, "get, POST")
		}
	}

	// An empty method filter matches everything.
	any := newRequestMatcher(RequestFilter{})
	if !any.match(&CapturedRequest{Method: "PATCH", URL: "http://x/"}) {
		t.Error("empty method filter should match any method")
	}
}
