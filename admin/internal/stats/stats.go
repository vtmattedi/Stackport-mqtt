// Package stats keeps the latest Mosquitto $SYS statistics in memory and serves them as
// a snapshot. Nothing is persisted: the broker republishes $SYS every sys_interval.
package stats

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

const sysPrefix = "$SYS/broker/"

// StaleAfter is how long without any $SYS update before a snapshot is flagged stale
// (the broker publishes every sys_interval, 10s by default).
const StaleAfter = 60 * time.Second

type metric struct{ group, name string }

// metrics maps a $SYS/broker/ topic suffix to the snapshot field it fills.
var metrics = map[string]metric{
	"clients/connected":    {"clients", "connected"},
	"clients/total":        {"clients", "total"},
	"clients/maximum":      {"clients", "maximum"},
	"clients/disconnected": {"clients", "disconnected"},

	"subscriptions/count":       {"store", "subscriptions"},
	"retained messages/count":   {"store", "retainedMessages"},
	"store/messages/count":      {"store", "storedMessages"},
	"store/messages/bytes":      {"store", "storedBytes"},
	"messages/inflight":         {"messages", "inflight"},
	"messages/received":         {"messages", "received"},
	"messages/sent":             {"messages", "sent"},
	"publish/messages/received": {"messages", "publishReceived"},
	"publish/messages/sent":     {"messages", "publishSent"},
	"publish/messages/dropped":  {"messages", "publishDropped"},

	"bytes/received":         {"bytes", "received"},
	"bytes/sent":             {"bytes", "sent"},
	"publish/bytes/received": {"bytes", "publishReceived"},
	"publish/bytes/sent":     {"bytes", "publishSent"},

	"heap/current": {"memory", "heapCurrent"},
	"heap/maximum": {"memory", "heapMaximum"},
}

func init() {
	for _, w := range []string{"1min", "5min", "15min"} {
		short := strings.TrimSuffix(w, "in")
		metrics["load/messages/received/"+w] = metric{"load", "messagesReceived" + short}
		metrics["load/messages/sent/"+w] = metric{"load", "messagesSent" + short}
		metrics["load/publish/received/"+w] = metric{"load", "publishReceived" + short}
		metrics["load/publish/sent/"+w] = metric{"load", "publishSent" + short}
		metrics["load/bytes/received/"+w] = metric{"load", "bytesReceived" + short}
		metrics["load/bytes/sent/"+w] = metric{"load", "bytesSent" + short}
		metrics["load/connections/"+w] = metric{"load", "connections" + short}
	}
}

// Snapshot is the JSON served by the API. Groups only contain values the broker has
// published, so a missing key means "not reported".
type Snapshot struct {
	Available     bool               `json:"available"`
	Stale         bool               `json:"stale"`
	UpdatedAt     *time.Time         `json:"updatedAt,omitempty"`
	Version       string             `json:"version,omitempty"`
	UptimeSeconds *int64             `json:"uptimeSeconds,omitempty"`
	Clients       map[string]float64 `json:"clients"`
	Store         map[string]float64 `json:"store"`
	Messages      map[string]float64 `json:"messages"`
	Bytes         map[string]float64 `json:"bytes"`
	Load          map[string]float64 `json:"load"`
	Memory        map[string]float64 `json:"memory"`
}

type Store struct {
	mu      sync.RWMutex
	values  map[string]map[string]float64
	version string
	uptime  *int64
	updated time.Time
}

func New() *Store {
	return &Store{values: map[string]map[string]float64{}}
}

// Handle is the MQTT message handler for $SYS/#.
func (s *Store) Handle(topic string, payload []byte) { s.Update(topic, payload, time.Now()) }

func (s *Store) Update(topic string, payload []byte, now time.Time) {
	suffix, ok := strings.CutPrefix(topic, sysPrefix)
	if !ok {
		return
	}
	text := strings.TrimSpace(string(payload))
	s.mu.Lock()
	defer s.mu.Unlock()
	switch suffix {
	case "version":
		s.version = strings.TrimPrefix(text, "mosquitto version ")
		s.updated = now
		return
	case "uptime":
		if n, err := strconv.ParseInt(strings.TrimSuffix(text, " seconds"), 10, 64); err == nil {
			s.uptime = &n
			s.updated = now
		}
		return
	}
	m, ok := metrics[suffix]
	if !ok {
		return
	}
	n, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return
	}
	if s.values[m.group] == nil {
		s.values[m.group] = map[string]float64{}
	}
	s.values[m.group][m.name] = n
	s.updated = now
}

func (s *Store) Snapshot() Snapshot { return s.SnapshotAt(time.Now()) }

func (s *Store) SnapshotAt(now time.Time) Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	group := func(name string) map[string]float64 {
		out := map[string]float64{}
		for k, v := range s.values[name] {
			out[k] = v
		}
		return out
	}
	snap := Snapshot{
		Version:  s.version,
		Clients:  group("clients"),
		Store:    group("store"),
		Messages: group("messages"),
		Bytes:    group("bytes"),
		Load:     group("load"),
		Memory:   group("memory"),
	}
	if s.uptime != nil {
		u := *s.uptime
		snap.UptimeSeconds = &u
	}
	if !s.updated.IsZero() {
		t := s.updated.UTC()
		snap.UpdatedAt = &t
		snap.Available = true
		snap.Stale = now.Sub(s.updated) > StaleAfter
	}
	return snap
}
