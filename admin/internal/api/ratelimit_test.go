package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func limitedHandler(l *failureLimiter) http.Handler {
	return l.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			w.WriteHeader(http.StatusUnauthorized)
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func hit(h http.Handler, path, ip string) int {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("X-Real-IP", ip)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRepeatedFailuresAreThrottledPerAddress(t *testing.T) {
	h := limitedHandler(newFailureLimiter(3, time.Minute))
	for i := 0; i < 3; i++ {
		if got := hit(h, "/bad", "1.1.1.1"); got != 401 {
			t.Fatalf("attempt %d: got %d, want 401", i, got)
		}
	}
	if got := hit(h, "/ok", "1.1.1.1"); got != 429 {
		t.Fatalf("blocked address: got %d, want 429", got)
	}
	if got := hit(h, "/ok", "2.2.2.2"); got != 200 {
		t.Fatalf("other address must be unaffected: got %d", got)
	}
}

func TestSuccessfulRequestsAreNeverCounted(t *testing.T) {
	h := limitedHandler(newFailureLimiter(2, time.Minute))
	for i := 0; i < 50; i++ {
		if got := hit(h, "/ok", "1.1.1.1"); got != 200 {
			t.Fatalf("got %d, want 200", got)
		}
	}
}

func TestForbiddenAlsoCountsAndWindowExpires(t *testing.T) {
	l := newFailureLimiter(2, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	h := limitedHandler(l)
	hit(h, "/forbidden", "1.1.1.1")
	hit(h, "/bad", "1.1.1.1")
	if got := hit(h, "/ok", "1.1.1.1"); got != 429 {
		t.Fatalf("got %d, want 429", got)
	}
	now = now.Add(time.Minute + time.Second)
	if got := hit(h, "/ok", "1.1.1.1"); got != 200 {
		t.Fatalf("after window: got %d, want 200", got)
	}
}

func TestZeroLimitDisablesThrottling(t *testing.T) {
	h := limitedHandler(newFailureLimiter(0, time.Minute))
	for i := 0; i < 20; i++ {
		hit(h, "/bad", "1.1.1.1")
	}
	if got := hit(h, "/ok", "1.1.1.1"); got != 200 {
		t.Fatalf("got %d, want 200", got)
	}
}

func TestFallsBackToSocketAddress(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "9.9.9.9:4242"
	if got := clientAddress(req); got != "9.9.9.9" {
		t.Fatalf("got %q", got)
	}
}
