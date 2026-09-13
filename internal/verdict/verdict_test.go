package verdict

import (
	"testing"

	"gobas/internal/target"
)

func aliveBaseline(status int) target.Baseline {
	return target.Baseline{Alive: true, StatusCode: status, RTTMS: 20}
}

func TestClassify(t *testing.T) {
	c := NewClassifier([]int{403, 405, 418, 429, 501})
	cases := []struct {
		name string
		ev   Evidence
		want Kind
	}{
		{"hit", Evidence{Matched: true, Status: 200, Baseline: aliveBaseline(200)}, HIT},
		{"hit even if blocked status", Evidence{Matched: true, Status: 403, Baseline: aliveBaseline(200)}, HIT},
		{"unreachable", Evidence{Status: 0, Baseline: target.Baseline{Alive: false}}, UNREACHABLE},
		{"unreachable port closed", Evidence{FailureText: "port closed or filtered", Baseline: aliveBaseline(200)}, UNREACHABLE},
		{"unreachable connection refused", Evidence{FailureText: "dial tcp 1.2.3.4:8009: connect: connection refused", Baseline: aliveBaseline(200)}, UNREACHABLE},
		{"unreachable no route", Evidence{FailureText: "dial tcp 1.2.3.4:443: connect: no route to host", Baseline: aliveBaseline(200)}, UNREACHABLE},
		{"timeout", Evidence{FailureText: "context deadline exceeded (Client.Timeout exceeded)", Baseline: aliveBaseline(200)}, TIMEOUT},
		{"timeout silent no response", Evidence{NoResponse: true, Baseline: aliveBaseline(200)}, TIMEOUT},
		{"timeout no response even with empty failure", Evidence{NoResponse: true, FailureText: "", Baseline: aliveBaseline(200)}, TIMEOUT},
		{"blocked status 403", Evidence{Status: 403, Baseline: aliveBaseline(200)}, BLOCKED},
		{"blocked status 429", Evidence{Status: 429, Baseline: aliveBaseline(200)}, BLOCKED},
		{"blocked waf fingerprint", Evidence{Status: 200, BodySnippet: "<html>Access blocked by SafeDog WAF</html>", Baseline: aliveBaseline(200)}, BLOCKED},
		{"blocked waf cloudflare", Evidence{Status: 503, BodySnippet: "cloudflare-nginx", Baseline: aliveBaseline(200)}, BLOCKED},
		{"blocked connection reset", Evidence{FailureText: "read tcp 1.2.3.4:1->5.6.7.8:80: connection reset by peer", Baseline: aliveBaseline(200)}, BLOCKED},
		{"miss with response", Evidence{Status: 200, Baseline: aliveBaseline(200)}, MISS},
		{"miss with 404 not blocked", Evidence{Status: 404, Baseline: aliveBaseline(404)}, MISS},
		{"error dns", Evidence{FailureText: "dial tcp: lookup nonexistent.example: no such host", Baseline: aliveBaseline(200)}, ERROR},
		{"fallback miss empty evidence", Evidence{Baseline: aliveBaseline(200)}, MISS},
	}
	for _, tc := range cases {
		if got := c.Classify(tc.ev); got != tc.want {
			t.Errorf("%s: Classify = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestParseResponseStatus(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello", 200},
		{"HTTP/1.1 302 Found\r\nLocation: /\r\n\r\nHTTP/1.1 403 Forbidden\r\n\r\nblocked", 403},
		{"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 0},
		{"", 0},
		{"garbage", 0},
	}
	for _, tc := range cases {
		if got := ParseResponseStatus(tc.in); got != tc.want {
			t.Errorf("ParseResponseStatus(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestBodySnippet(t *testing.T) {
	resp := "HTTP/1.1 403 Forbidden\r\nServer: safedog\r\n\r\n<html>blocked</html>"
	if got := BodySnippet(resp); got != "<html>blocked</html>" {
		t.Errorf("BodySnippet = %q", got)
	}
	if got := BodySnippet(""); got != "" {
		t.Errorf("BodySnippet empty = %q", got)
	}
}
