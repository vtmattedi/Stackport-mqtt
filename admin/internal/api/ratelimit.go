package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxTrackedClients = 10_000

// failureLimiter throttles callers that keep presenting bad tokens. It counts only
// 401/403 responses per client address in a fixed window, and answers 429 once a caller
// reaches the limit until the window ends. Successful requests are never counted, so
// a healthy BFF is unaffected. State is in memory and best-effort by design.
type failureLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	clients map[string]*bucket
}

type bucket struct {
	start    time.Time
	failures int
}

func newFailureLimiter(limit int, window time.Duration) *failureLimiter {
	return &failureLimiter{limit: limit, window: window, now: time.Now, clients: map[string]*bucket{}}
}

func (l *failureLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.clients[key]
	if !ok {
		return false
	}
	if l.now().Sub(b.start) >= l.window {
		delete(l.clients, key)
		return false
	}
	return b.failures >= l.limit
}

func (l *failureLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.clients[key]
	if !ok || now.Sub(b.start) >= l.window {
		if len(l.clients) >= maxTrackedClients {
			l.sweep(now)
		}
		if len(l.clients) >= maxTrackedClients {
			return // table full of live offenders: stop growing rather than evict them
		}
		b = &bucket{start: now}
		l.clients[key] = b
	}
	b.failures++
}

func (l *failureLimiter) sweep(now time.Time) {
	for k, b := range l.clients {
		if now.Sub(b.start) >= l.window {
			delete(l.clients, k)
		}
	}
}

// middleware wraps next. A limit of zero or less disables throttling.
func (l *failureLimiter) middleware(next http.Handler) http.Handler {
	if l.limit <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientAddress(r)
		if l.blocked(key) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too_many_failures")
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden {
			l.fail(key)
		}
	})
}

// clientAddress prefers the address Stackport's nginx records in X-Real-IP, which is
// the real caller; direct connections fall back to the socket address.
func clientAddress(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
