package main

import (
	"cmp"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"
)

const (
	topic    = "a-topic"
	lease    = 24 * time.Hour
	formType = "application/x-www-form-urlencoded"
	maxForm  = 16 << 10 // bytes in a subscription request body
)

// limits bound the hub's outbound work and storage.
type limits struct {
	exchangeTimeout time.Duration // one callback request
	broadcastBudget time.Duration // one whole publish
	maxVerifying    int
	maxPublishing   int
	maxCallbacks    int // distinct callbacks, stored or being verified
}

var defaultLimits = limits{
	exchangeTimeout: 5 * time.Second,
	broadcastBudget: 8 * time.Second,
	maxVerifying:    16,
	maxPublishing:   4,
	maxCallbacks:    1000,
}

type subscription struct {
	callback  string
	secret    string
	expiresAt time.Time
	revision  uint64
}

type event struct {
	EventID     string    `json:"event_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Message     string    `json:"message"`
}

// summary counts the recipients of one broadcast:
// selected = attempted + skipped_expired + not_attempted, and
// attempted = acknowledged + failed.
type summary struct {
	EventID        string `json:"event_id"`
	Selected       int    `json:"selected"`
	Attempted      int    `json:"attempted"`
	Acknowledged   int    `json:"acknowledged"`
	Failed         int    `json:"failed"`
	SkippedExpired int    `json:"skipped_expired"`
	NotAttempted   int    `json:"not_attempted"`
}

type outcome int

const (
	acknowledged outcome = iota
	failed
	skippedExpired
	notAttempted
)

func (s *summary) add(o outcome) {
	s.Selected++
	switch o {
	case acknowledged:
		s.Attempted++
		s.Acknowledged++
	case failed:
		s.Attempted++
		s.Failed++
	case skippedExpired:
		s.SkippedExpired++
	case notAttempted:
		s.NotAttempted++
	}
}

// Hub holds the subscriptions and tracks the verifications it has admitted.
// The fields after mu are guarded by it.
type Hub struct {
	limits
	mux    http.Handler
	client *http.Client
	log    *slog.Logger
	now    func() time.Time
	tasks  sync.WaitGroup // admitted verifications

	mu            sync.Mutex
	closed        bool
	lastRevision  uint64
	verifications int            // in progress
	verifying     map[string]int // in progress, per callback
	publishing    int
	broadcasts    uint64 // started so far; rotates where the next one starts
	subs          map[string]subscription
}

var errShuttingDown = errors.New("hub is shutting down")

func (h *Hub) isLive(s subscription) bool { return h.now().Before(s.expiresAt) }

func (h *Hub) stopAdmission() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
}

func (h *Hub) lookup(callback string) (subscription, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sub, ok := h.subs[callback]
	return sub, ok
}

// liveCallbacks returns the callbacks of live subscriptions in revision order.
func (h *Hub) liveCallbacks() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepExpiredLocked()
	live := slices.Collect(maps.Values(h.subs))
	live = slices.DeleteFunc(live, func(s subscription) bool { return !h.isLive(s) })
	slices.SortFunc(live, func(a, b subscription) int { return cmp.Compare(a.revision, b.revision) })
	callbacks := make([]string, len(live))
	for i, s := range live {
		callbacks[i] = s.callback
	}
	return callbacks
}

func (h *Hub) countBroadcast() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broadcasts++
	return h.broadcasts - 1
}

// reservePublish claims a publish slot without waiting for one.
func (h *Hub) reservePublish() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.closed:
		return errShuttingDown
	case h.publishing >= h.maxPublishing:
		return errors.New("too many publishes in progress")
	}
	h.publishing++
	return nil
}

func (h *Hub) releasePublish() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publishing--
}
