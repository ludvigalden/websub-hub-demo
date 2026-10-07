// Command websub-hub-demo is a minimal WebSub hub: it verifies subscriber
// intent and distributes HMAC-SHA-256-signed JSON notifications.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	topic          = "a-topic"
	leaseSeconds   = 86400
	maxFormBytes   = 16 << 10
	maxSecretBytes = 199
)

type subscription struct {
	callback  string
	secret    []byte
	expiresAt time.Time
	revision  uint64
}

type summary struct {
	EventID        string `json:"event_id"`
	Selected       int    `json:"selected"`
	Attempted      int    `json:"attempted"`
	Acknowledged   int    `json:"acknowledged"`
	Failed         int    `json:"failed"`
	SkippedExpired int    `json:"skipped_expired"`
}

type Hub struct {
	client  *http.Client
	now     func() time.Time
	pending sync.WaitGroup

	mu       sync.Mutex
	revision uint64
	subs     map[string]subscription
}

func NewHub(timeout time.Duration) *Hub {
	return &Hub{
		client: &http.Client{
			Timeout: timeout,
			// A redirect must not turn a failed callback exchange into a success.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:  time.Now,
		subs: make(map[string]subscription),
	}
}

func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /{$}", h.handleSubscribe)
	mux.HandleFunc("POST /publish", h.handlePublish)
	return mux
}

func (h *Hub) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		http.Error(w, "expected application/x-www-form-urlencoded", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "malformed form body", http.StatusBadRequest)
		return
	}
	sub, err := parseSubscription(r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	h.revision++
	sub.revision = h.revision
	h.mu.Unlock()

	h.pending.Go(func() { h.verify(sub) })
	w.WriteHeader(http.StatusAccepted)
}

func parseSubscription(form url.Values) (subscription, error) {
	for _, k := range []string{"hub.mode", "hub.callback", "hub.topic", "hub.secret", "hub.lease_seconds"} {
		if len(form[k]) > 1 {
			return subscription{}, errors.New("duplicate " + k)
		}
	}
	if form.Get("hub.mode") != "subscribe" {
		return subscription{}, errors.New("hub.mode must be subscribe")
	}
	callback := form.Get("hub.callback")
	u, err := url.Parse(callback)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return subscription{}, errors.New("hub.callback must be an absolute http(s) URL without credentials or fragment")
	}
	if form.Get("hub.topic") != topic {
		return subscription{}, errors.New("unknown hub.topic")
	}
	secret := form.Get("hub.secret")
	if secret == "" || len(secret) > maxSecretBytes {
		return subscription{}, errors.New("hub.secret must be 1-199 bytes")
	}
	if ls := form.Get("hub.lease_seconds"); ls != "" {
		if n, err := strconv.ParseUint(ls, 10, 32); err != nil || n == 0 {
			return subscription{}, errors.New("hub.lease_seconds must be a positive integer")
		}
	}
	return subscription{callback: callback, secret: []byte(secret)}, nil
}

func (h *Hub) verify(sub subscription) {
	want := rand.Text()

	u, err := url.Parse(sub.callback)
	if err != nil {
		slog.Error("verification failed", "subscription", sub.revision, "err", err)
		return
	}
	query := url.Values{
		"hub.mode":          {"subscribe"},
		"hub.topic":         {topic},
		"hub.challenge":     {want},
		"hub.lease_seconds": {strconv.Itoa(leaseSeconds)},
	}.Encode()
	if u.RawQuery != "" {
		query = u.RawQuery + "&" + query
	}
	u.RawQuery = query

	started := h.now()
	resp, err := h.client.Get(u.String())
	if err != nil {
		slog.Warn("verification failed", "subscription", sub.revision, "err", err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(want))+1))
	resp.Body.Close()
	if err != nil || resp.StatusCode/100 != 2 || string(body) != want {
		slog.Warn("verification failed", "subscription", sub.revision, "status", resp.StatusCode)
		return
	}

	sub.expiresAt = started.Add(leaseSeconds * time.Second)
	h.mu.Lock()
	defer h.mu.Unlock()
	// The newest accepted request that verifies wins, whatever order
	// verifications complete in.
	if prev, ok := h.subs[sub.callback]; ok && prev.revision >= sub.revision {
		slog.Info("verified but superseded", "subscription", sub.revision, "by", prev.revision)
		return
	}
	h.subs[sub.callback] = sub
	slog.Info("verified", "subscription", sub.revision)
}

func (h *Hub) handlePublish(w http.ResponseWriter, r *http.Request) {
	sum := summary{EventID: rand.Text()}
	body, err := json.Marshal(map[string]any{
		"event_id":     sum.EventID,
		"generated_at": h.now().UTC(),
		"message":      "Generated by the WebSub demonstration hub",
	})
	if err != nil {
		http.Error(w, "could not generate payload", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	var recipients []subscription
	for _, sub := range h.subs {
		if h.now().Before(sub.expiresAt) {
			recipients = append(recipients, sub)
		}
	}
	h.mu.Unlock()
	slices.SortFunc(recipients, func(a, b subscription) int { return cmp.Compare(a.revision, b.revision) })

	sum.Selected = len(recipients)
	for _, sub := range recipients {
		if !h.now().Before(sub.expiresAt) {
			sum.SkippedExpired++
			continue
		}
		sum.Attempted++
		if err := h.deliver(sub, body); err != nil {
			sum.Failed++
			slog.Warn("delivery failed", "event", sum.EventID, "subscription", sub.revision, "err", err)
			continue
		}
		sum.Acknowledged++
	}
	slog.Info("published", "event", sum.EventID, "selected", sum.Selected, "acknowledged", sum.Acknowledged, "failed", sum.Failed, "skipped_expired", sum.SkippedExpired)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sum)
}

func (h *Hub) deliver(sub subscription, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, sub.callback, bytes.NewReader(body))
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, sub.secret)
	mac.Write(body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New(resp.Status)
	}
	return nil
}

func main() {
	hub := NewHub(5 * time.Second)
	srv := &http.Server{Addr: ":8080", Handler: hub.Handler(), ReadHeaderTimeout: 5 * time.Second}

	drained := make(chan struct{})
	go func() {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		<-ctx.Done()
		if err := srv.Shutdown(context.Background()); err != nil {
			slog.Error("shutdown failed", "err", err)
		}
		close(drained)
	}()

	slog.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
	<-drained
	hub.pending.Wait()
}
