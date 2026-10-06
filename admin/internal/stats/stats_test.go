package stats

import (
	"testing"
	"time"
)

func TestSnapshotCollectsKnownTopicsOnly(t *testing.T) {
	s := New()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for topic, payload := range map[string]string{
		"$SYS/broker/version":                     "mosquitto version 2.1.2",
		"$SYS/broker/uptime":                      "3600 seconds",
		"$SYS/broker/clients/connected":           "3",
		"$SYS/broker/clients/total":               "5",
		"$SYS/broker/subscriptions/count":         "7",
		"$SYS/broker/retained messages/count":     "42",
		"$SYS/broker/messages/received":           "1000",
		"$SYS/broker/load/messages/received/1min": "12.5",
		"$SYS/broker/load/bytes/sent/15min":       "99.25",
		"$SYS/broker/heap/current":                "123456",
		"$SYS/broker/unknown/thing":               "9",
		"$SYS/broker/clients/disconnected":        "not-a-number",
		"other/topic":                             "1",
	} {
		s.Update(topic, []byte(payload), now)
	}
	snap := s.SnapshotAt(now.Add(5 * time.Second))

	if !snap.Available || snap.Stale {
		t.Fatalf("available=%v stale=%v", snap.Available, snap.Stale)
	}
	if snap.Version != "2.1.2" || snap.UptimeSeconds == nil || *snap.UptimeSeconds != 3600 {
		t.Fatalf("version/uptime wrong: %q %v", snap.Version, snap.UptimeSeconds)
	}
	checks := []struct {
		group map[string]float64
		key   string
		want  float64
	}{
		{snap.Clients, "connected", 3}, {snap.Clients, "total", 5},
		{snap.Store, "subscriptions", 7}, {snap.Store, "retainedMessages", 42},
		{snap.Messages, "received", 1000},
		{snap.Load, "messagesReceived1m", 12.5}, {snap.Load, "bytesSent15m", 99.25},
		{snap.Memory, "heapCurrent", 123456},
	}
	for _, c := range checks {
		if got, ok := c.group[c.key]; !ok || got != c.want {
			t.Errorf("%s = %v (present=%v), want %v", c.key, got, ok, c.want)
		}
	}
	if _, ok := snap.Clients["disconnected"]; ok {
		t.Error("a non-numeric value must be ignored")
	}
}

func TestSnapshotBeforeAnyDataIsUnavailable(t *testing.T) {
	snap := New().Snapshot()
	if snap.Available || snap.UpdatedAt != nil || snap.Clients == nil {
		t.Fatalf("unexpected empty snapshot: %+v", snap)
	}
}

func TestSnapshotGoesStale(t *testing.T) {
	s := New()
	now := time.Now()
	s.Update("$SYS/broker/clients/connected", []byte("1"), now)
	if s.SnapshotAt(now.Add(StaleAfter - time.Second)).Stale {
		t.Error("should not be stale yet")
	}
	if !s.SnapshotAt(now.Add(StaleAfter + time.Second)).Stale {
		t.Error("should be stale")
	}
}
