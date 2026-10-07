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

// Hub admits requests and verifications under mu and tracks them in tasks, so
// once closed is set nothing new can start and tasks.Wait covers all work.
type Hub struct {
	mux                   *http.ServeMux
	client                *http.Client
	log                   *slog.Logger
	now                   func() time.Time
	timeout, budget       time.Duration // per callback exchange, per broadcast
	maxVerifying, maxSubs int
	ctx                   context.Context // hub-owned lifetime of verifications
	abort                 context.CancelFunc
	tasks                 sync.WaitGroup

	mu        sync.Mutex
	closed    bool
	revision  uint64
	pending   int
	subs      map[string]subscription
	verifying map[string]int // outstanding verifications per callback
}

func NewHub() *Hub {
	h := &Hub{
		mux: http.NewServeMux(), log: slog.Default(), now: time.Now,
		// A redirect must not turn a failed callback exchange into a success.
		client:  &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: 5 * time.Second, budget: 8 * time.Second, maxVerifying: 16, maxSubs: 1000,
		subs: map[string]subscription{}, verifying: map[string]int{},
	}
	h.ctx, h.abort = context.WithCancel(context.Background())
	h.mux.HandleFunc("POST /{$}", h.handleSubscribe)
	h.mux.HandleFunc("POST /publish", h.handlePublish)
	return h
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.admit(nil); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer h.tasks.Done()
	h.mux.ServeHTTP(w, r)
}

// admit registers one task and reclaims expired records. Given a
// subscription it also assigns its revision and claims verification and
// storage capacity, all before any 202 is sent.
func (h *Hub) admit(sub *subscription) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// An expired record stays while its callback has a verification
	// outstanding, as the guard against resurrecting a superseded secret.
	maps.DeleteFunc(h.subs, func(cb string, s subscription) bool { return !h.live(s) && h.verifying[cb] == 0 })
	switch {
	case h.closed:
		return errors.New("hub is shutting down")
	case sub == nil:
	case h.pending >= h.maxVerifying:
		return errors.New("too many verifications in progress")
	case h.subs[sub.callback].callback == "" && h.verifying[sub.callback] == 0 && len(h.subs)+len(h.verifying) >= h.maxSubs:
		return errors.New("subscription limit reached")
	default:
		h.revision, h.pending, h.verifying[sub.callback] = h.revision+1, h.pending+1, h.verifying[sub.callback]+1
		sub.revision = h.revision
	}
	h.tasks.Add(1)
	return nil
}

func (h *Hub) live(s subscription) bool { return h.now().Before(s.expiresAt) }

func (h *Hub) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	sub, code, err := parseSubscription(w, r)
	if err == nil {
		code, err = http.StatusServiceUnavailable, h.admit(&sub)
	}
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	// The 202 is complete and flushed before the callback exchange starts.
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
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "":
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
