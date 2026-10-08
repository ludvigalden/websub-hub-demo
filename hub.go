package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const defaultLease = 24 * time.Hour

type key struct{ topic, callback string }

type subscription struct {
	key
	secret  string
	lease   time.Duration
	expires time.Time
	seq     uint64 // order of arrival; a stale verification must not win
}

type Hub struct {
	client *http.Client

	mu   sync.Mutex // guards seq and subs; never held during network I/O
	seq  uint64
	subs map[key]subscription
}

func NewHub() *Hub {
	return &Hub{
		client: &http.Client{
			Timeout: 5 * time.Second,
			// A redirect would let another URL answer the challenge.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		subs: map[key]subscription{},
	}
}

func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /{$}", h.handleSubscribe)
	mux.HandleFunc("POST /publish", h.handlePublish)
	return mux
}

func (h *Hub) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	sub, err := parseSubscription(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	h.seq++
	sub.seq = h.seq
	h.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
	http.NewResponseController(w).Flush() // answer before the callback is contacted
	go h.verify(sub)
}

func parseSubscription(r *http.Request) (subscription, error) {
	sub := subscription{
		key:    key{topic: r.PostFormValue("hub.topic"), callback: r.PostFormValue("hub.callback")},
		secret: r.PostFormValue("hub.secret"),
		lease:  defaultLease,
	}
	u, err := url.Parse(sub.callback)
	switch {
	case r.PostFormValue("hub.mode") != "subscribe":
		return sub, errors.New("hub.mode must be subscribe")
	case sub.topic == "":
		return sub, errors.New("hub.topic is required")
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return sub, errors.New("hub.callback must be an absolute http(s) URL")
	case sub.secret == "" || len(sub.secret) >= 200:
		// Optional in WebSub, required here because every delivery is signed.
		return sub, errors.New("hub.secret must be 1-199 bytes")
	}
	if v := r.PostFormValue("hub.lease_seconds"); v != "" {
		// 32 bits keeps the duration from overflowing.
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 {
			return sub, errors.New("hub.lease_seconds must be a positive integer")
		}
		sub.lease = time.Duration(n) * time.Second
	}
	return sub, nil
}

// verify asks the callback to echo a random challenge and stores the
// subscription only if the body matches exactly.
func (h *Hub) verify(sub subscription) {
	challenge := rand.Text()
	u, _ := url.Parse(sub.callback) // validated in parseSubscription
	q := url.Values{
		"hub.mode":          {"subscribe"},
		"hub.topic":         {sub.topic},
		"hub.challenge":     {challenge},
		"hub.lease_seconds": {strconv.Itoa(int(sub.lease.Seconds()))},
	}.Encode()
	if u.RawQuery != "" {
		q = u.RawQuery + "&" + q
	}
	u.RawQuery = q

	sub.expires = time.Now().Add(sub.lease) // WebSub counts the lease from the request
	resp, err := h.client.Get(u.String())
	if err != nil {
		slog.Warn("verification failed", "callback", sub.callback, "err", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(challenge))+1))
	if err != nil || resp.StatusCode/100 != 2 || string(body) != challenge {
		slog.Warn("verification rejected", "callback", sub.callback, "status", resp.StatusCode)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.subs[sub.key]; ok && cur.seq > sub.seq {
		return
	}
	h.subs[sub.key] = sub
	slog.Info("verified", "topic", sub.topic, "callback", sub.callback, "lease", sub.lease)
}

type event struct {
	EventID     string    `json:"event_id"`
	PublishedAt time.Time `json:"published_at"`
	Message     string    `json:"message"`
}

func (h *Hub) handlePublish(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	ev := event{EventID: rand.Text(), PublishedAt: now.UTC(), Message: "hello from the hub"}
	body, _ := json.Marshal(ev) // cannot fail for this struct; every recipient gets these bytes

	h.mu.Lock()
	var live []subscription
	for _, sub := range h.subs {
		if now.Before(sub.expires) {
			live = append(live, sub)
		}
	}
	h.mu.Unlock()

	delivered := 0
	for _, sub := range live {
		if err := h.deliver(sub, body); err != nil {
			slog.Warn("delivery failed", "callback", sub.callback, "err", err)
			continue
		}
		delivered++
	}
	slog.Info("published", "event_id", ev.EventID, "subscribers", len(live), "delivered", delivered)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"event_id": ev.EventID, "subscribers": len(live), "delivered": delivered,
	})
}

func (h *Hub) deliver(sub subscription, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, sub.callback, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature", sign(sub.secret, body))
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) // lets the connection be reused
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New(resp.Status)
	}
	return nil
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
