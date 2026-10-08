package main

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	topic    = "a-topic"
	lease    = 24 * time.Hour
	formType = "application/x-www-form-urlencoded"
	maxForm  = 16 << 10
)

type subscription struct {
	callback, secret string
	expiresAt        time.Time
	revision         uint64
}

// selected = attempted + skipped_expired + not_attempted; attempted = acknowledged + failed.
type summary struct {
	EventID        string `json:"event_id"`
	Selected       int    `json:"selected"`
	Attempted      int    `json:"attempted"`
	Acknowledged   int    `json:"acknowledged"`
	Failed         int    `json:"failed"`
	SkippedExpired int    `json:"skipped_expired"`
	NotAttempted   int    `json:"not_attempted"`
}

type event struct {
	EventID     string    `json:"event_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Message     string    `json:"message"`
}

// Hub admits work under mu and tracks it in tasks, so once closed is set
// nothing new is admitted and tasks.Wait covers all admitted work.
type Hub struct {
	mux                   *http.ServeMux
	client                *http.Client
	log                   *slog.Logger
	now                   func() time.Time
	timeout, budget       time.Duration // per callback exchange, per broadcast
	maxVerifying, maxSubs int
	maxPublishing         int
	ctx                   context.Context // hub-owned lifetime of verifications and requests
	abort                 context.CancelFunc
	tasks                 sync.WaitGroup

	mu         sync.Mutex
	closed     bool
	revision   uint64
	pending    int
	publishing int
	broadcasts uint64 // rotates where each broadcast starts
	subs       map[string]subscription
	verifying  map[string]int // outstanding verifications per callback
}

func NewHub() *Hub {
	h := &Hub{
		mux: http.NewServeMux(), log: slog.Default(), now: time.Now,
		// A redirect must not turn a failed callback exchange into a success.
		client:  &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: 5 * time.Second, budget: 8 * time.Second, maxVerifying: 16, maxSubs: 1000, maxPublishing: 4,
		subs: map[string]subscription{}, verifying: map[string]int{},
	}
	h.ctx, h.abort = context.WithCancel(context.Background())
	h.mux.HandleFunc("POST /{$}", h.handleSubscribe)
	h.mux.HandleFunc("POST /publish", h.handlePublish)
	return h
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.admitRequest(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer h.tasks.Done()
	h.mux.ServeHTTP(w, r)
}

// openLocked reclaims expired records and reports whether admission is open.
// An expired record stays while its callback has a verification
// outstanding, as the guard against resurrecting a superseded secret.
func (h *Hub) openLocked() error {
	maps.DeleteFunc(h.subs, func(cb string, s subscription) bool { return !h.live(s) && h.verifying[cb] == 0 })
	if h.closed {
		return errors.New("hub is shutting down")
	}
	return nil
}

func (h *Hub) admitRequest() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.openLocked(); err != nil {
		return err
	}
	h.tasks.Add(1)
	return nil
}

// admitVerification assigns sub its revision and claims verification and
// storage capacity for it, all before any 202 is sent.
func (h *Hub) admitVerification(sub *subscription) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.openLocked(); err != nil {
		return err
	}
	if h.pending >= h.maxVerifying {
		return errors.New("too many verifications in progress")
	}
	if _, known := h.subs[sub.callback]; !known && h.verifying[sub.callback] == 0 && h.occupiedLocked() >= h.maxSubs {
		return errors.New("subscription limit reached")
	}
	h.revision++
	sub.revision = h.revision
	h.pending++
	h.verifying[sub.callback]++
	h.tasks.Add(1)
	return nil
}

// occupiedLocked counts distinct callbacks, stored or being verified; a
// stored callback with a renewal outstanding counts once.
func (h *Hub) occupiedLocked() int {
	n := len(h.subs)
	for cb := range h.verifying {
		if _, ok := h.subs[cb]; !ok {
			n++
		}
	}
	return n
}

// finishVerification releases sub's reservation and stores it if it verified,
// unless a newer revision is already stored: the newest accepted request that
// verifies wins, whatever the completion order. It returns that newer revision.
func (h *Hub) finishVerification(sub subscription, verified bool) (supersededBy uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pending--
	h.verifying[sub.callback]--
	if h.verifying[sub.callback] == 0 {
		delete(h.verifying, sub.callback)
	}
	if prev, ok := h.subs[sub.callback]; ok && prev.revision > sub.revision {
		return prev.revision
	}
	if verified {
		h.subs[sub.callback] = sub
	}
	return 0
}

func (h *Hub) live(s subscription) bool { return h.now().Before(s.expiresAt) }

func (h *Hub) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	sub, code, err := parseSubscription(w, r)
	if err == nil {
		code, err = http.StatusServiceUnavailable, h.admitVerification(&sub)
	}
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	// The 202 is complete and flushed before the callback exchange starts. A
	// failed flush is logged and verification still goes ahead: the
	// reservation is already held, and the challenge alone decides the outcome.
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusAccepted)
	if err := http.NewResponseController(w).Flush(); err != nil {
		h.log.Warn("acceptance not flushed", "subscription", sub.revision, "err", err)
	}
	go h.verify(h.ctx, sub)
}

func parseSubscription(w http.ResponseWriter, r *http.Request) (subscription, int, error) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != formType {
		return subscription{}, http.StatusUnsupportedMediaType, errors.New("expected " + formType)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return subscription{}, http.StatusRequestEntityTooLarge, errors.New("request body too large")
		}
		return subscription{}, http.StatusBadRequest, errors.New("malformed form body")
	}
	f, sub := r.PostForm, subscription{callback: r.PostForm.Get("hub.callback"), secret: r.PostForm.Get("hub.secret")}
	u, err := url.Parse(sub.callback)
	n, leaseErr := strconv.ParseUint(f.Get("hub.lease_seconds"), 10, 32)
	bad := func(msg string) (subscription, int, error) {
		return subscription{}, http.StatusBadRequest, errors.New(msg)
	}
	switch {
	case slices.ContainsFunc([]string{"hub.mode", "hub.callback", "hub.topic", "hub.secret", "hub.lease_seconds"},
		func(k string) bool { return len(f[k]) > 1 }):
		return bad("duplicate hub.* parameter")
	case f.Get("hub.mode") != "subscribe":
		return bad("hub.mode must be subscribe")
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || strings.Contains(sub.callback, "#"):
		return bad("hub.callback must be an absolute http(s) URL with a host, without credentials or fragment")
	case f.Get("hub.topic") != topic:
		return bad("unknown hub.topic")
	case sub.secret == "" || len(sub.secret) > 199:
		return bad("hub.secret must be 1-199 bytes")
	case f.Has("hub.lease_seconds") && (leaseErr != nil || n == 0):
		return bad("hub.lease_seconds must be a positive integer")
	}
	return sub, 0, nil
}
