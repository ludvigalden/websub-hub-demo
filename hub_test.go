package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSubscriber echoes challenges and records deliveries.
type fakeSubscriber struct {
	*httptest.Server
	mu         sync.Mutex
	queries    []url.Values
	deliveries []*http.Request
	bodies     [][]byte
}

func newSubscriber(t *testing.T, path string) *fakeSubscriber {
	t.Helper()
	s := &fakeSubscriber{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Method == http.MethodGet {
			s.queries = append(s.queries, r.URL.Query())
			io.WriteString(w, r.URL.Query().Get("hub.challenge"))
			return
		}
		s.deliveries = append(s.deliveries, r)
		s.bodies = append(s.bodies, body)
	}))
	t.Cleanup(s.Close)
	s.URL += path
	return s
}

func (s *fakeSubscriber) received() ([]url.Values, []*http.Request, [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries, s.deliveries, s.bodies
}

func subscribeForm(callback, secret string) url.Values {
	return url.Values{
		"hub.mode":     {"subscribe"},
		"hub.topic":    {"a-topic"},
		"hub.callback": {callback},
		"hub.secret":   {secret},
	}
}

func stored(h *Hub, callback string) (subscription, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sub, ok := h.subs[key{"a-topic", callback}]
	return sub, ok
}

// waitFor polls a condition that another goroutine makes true; the deadline
// only turns a hang into a failure.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// publish uses t.Error so it is safe to call from other goroutines.
func publish(t *testing.T, hubURL string) map[string]any {
	t.Helper()
	resp, err := http.Post(hubURL+"/publish", "", nil)
	if err != nil {
		t.Error(err)
		return nil
	}
	defer resp.Body.Close()
	var sum map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&sum); err != nil {
		t.Error(err)
	}
	return sum
}

func TestSubscribeValidation(t *testing.T) {
	hub := httptest.NewServer(NewHub().Handler())
	defer hub.Close()
	sub := newSubscriber(t, "/cb")

	tests := []struct {
		name, field, value string
		want               int
	}{
		{"valid", "", "", http.StatusAccepted},
		{"valid lease", "hub.lease_seconds", "60", http.StatusAccepted},
		{"unsubscribe", "hub.mode", "unsubscribe", http.StatusBadRequest},
		{"missing topic", "hub.topic", "", http.StatusBadRequest},
		{"relative callback", "hub.callback", "/cb", http.StatusBadRequest},
		{"non-http callback", "hub.callback", "ftp://example.com/cb", http.StatusBadRequest},
		{"missing secret", "hub.secret", "", http.StatusBadRequest},
		{"long secret", "hub.secret", strings.Repeat("s", 200), http.StatusBadRequest},
		{"zero lease", "hub.lease_seconds", "0", http.StatusBadRequest},
		{"text lease", "hub.lease_seconds", "soon", http.StatusBadRequest},
		{"huge lease", "hub.lease_seconds", "99999999999", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := subscribeForm(sub.URL, "secret")
			if tt.field != "" {
				form.Set(tt.field, tt.value)
			}
			resp, err := http.PostForm(hub.URL, form)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestVerificationStoresSubscription(t *testing.T) {
	h := NewHub()
	hub := httptest.NewServer(h.Handler())
	defer hub.Close()
	sub := newSubscriber(t, "/cb?id=7&id=8")

	form := subscribeForm(sub.URL, "secret")
	form.Set("hub.lease_seconds", "60")
	resp, err := http.PostForm(hub.URL, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d, want 202", resp.StatusCode)
	}
	waitFor(t, "stored subscription", func() bool { _, ok := stored(h, sub.URL); return ok })

	s, _ := stored(h, sub.URL)
	if s.secret != "secret" || time.Until(s.expires) > time.Minute || time.Until(s.expires) < 50*time.Second {
		t.Fatalf("stored %+v", s)
	}
	queries, _, _ := sub.received()
	q := queries[0]
	if q.Get("hub.mode") != "subscribe" || q.Get("hub.topic") != "a-topic" ||
		q.Get("hub.lease_seconds") != "60" || q.Get("hub.challenge") == "" {
		t.Fatalf("verification query %v", q)
	}
	if got := q["id"]; len(got) != 2 || got[0] != "7" || got[1] != "8" {
		t.Fatalf("callback query not preserved: %v", q)
	}
}

func TestVerificationRejected(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Store(true)
		io.WriteString(w, r.URL.Query().Get("hub.challenge"))
	}))
	defer target.Close()

	tests := map[string]http.HandlerFunc{
		"wrong challenge": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, r.URL.Query().Get("hub.challenge")+"x")
		},
		"non-2xx": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, r.URL.Query().Get("hub.challenge"))
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"?"+r.URL.RawQuery, http.StatusFound)
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			cb := httptest.NewServer(handler)
			defer cb.Close()
			h := NewHub()
			h.verify(subscription{key: key{"a-topic", cb.URL}, secret: "s", lease: time.Hour})
			if _, ok := stored(h, cb.URL); ok {
				t.Fatal("subscription stored")
			}
		})
	}
	if redirected.Load() {
		t.Fatal("hub followed a redirect")
	}
}

func TestStaleVerificationDoesNotOverwrite(t *testing.T) {
	sub := newSubscriber(t, "/cb")
	h := NewHub()
	older := subscription{key: key{"a-topic", sub.URL}, secret: "old", lease: time.Hour, seq: 1}
	newer := older
	newer.secret, newer.seq = "new", 2

	h.verify(newer)
	h.verify(older)
	if s, _ := stored(h, sub.URL); s.secret != "new" {
		t.Fatalf("stored secret %q, want the newer one", s.secret)
	}
}

func TestPublishSignsExactBody(t *testing.T) {
	h := NewHub()
	hub := httptest.NewServer(h.Handler())
	defer hub.Close()
	a, b := newSubscriber(t, "/a"), newSubscriber(t, "/b")
	h.verify(subscription{key: key{"a-topic", a.URL}, secret: "secret-a", lease: time.Hour})
	h.verify(subscription{key: key{"a-topic", b.URL}, secret: "secret-b", lease: time.Hour})

	sum := publish(t, hub.URL)
	if sum["subscribers"] != 2.0 || sum["delivered"] != 2.0 {
		t.Fatalf("summary %v", sum)
	}
	for secret, s := range map[string]*fakeSubscriber{"secret-a": a, "secret-b": b} {
		_, reqs, bodies := s.received()
		if len(reqs) != 1 {
			t.Fatalf("%d deliveries, want 1", len(reqs))
		}
		r, body := reqs[0], bodies[0]
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("delivery %s with Content-Type %q", r.Method, r.Header.Get("Content-Type"))
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); r.Header.Get("X-Hub-Signature") != want {
			t.Fatalf("signature %q, want %q", r.Header.Get("X-Hub-Signature"), want)
		}
		var ev event
		if err := json.Unmarshal(body, &ev); err != nil || ev.EventID != sum["event_id"] {
			t.Fatalf("body %s does not carry event %v", body, sum["event_id"])
		}
	}
}

func TestPublishSkipsExpired(t *testing.T) {
	h := NewHub()
	hub := httptest.NewServer(h.Handler())
	defer hub.Close()
	live, expired := newSubscriber(t, "/live"), newSubscriber(t, "/expired")
	h.verify(subscription{key: key{"a-topic", live.URL}, secret: "s", lease: time.Hour})
	h.verify(subscription{key: key{"a-topic", expired.URL}, secret: "s", lease: time.Hour})
	h.mu.Lock()
	k := key{"a-topic", expired.URL}
	s := h.subs[k]
	s.expires = time.Now().Add(-time.Second)
	h.subs[k] = s
	h.mu.Unlock()

	if sum := publish(t, hub.URL); sum["subscribers"] != 1.0 || sum["delivered"] != 1.0 {
		t.Fatalf("summary %v", sum)
	}
	if _, reqs, _ := expired.received(); len(reqs) != 0 {
		t.Fatal("expired subscriber received a delivery")
	}
	if _, reqs, _ := live.received(); len(reqs) != 1 {
		t.Fatal("live subscriber missed the delivery")
	}
}

// TestConcurrentSubscribeAndPublish is meant for -race: registrations,
// verifications and publishes all touch the subscriber map at once.
func TestConcurrentSubscribeAndPublish(t *testing.T) {
	h := NewHub()
	hub := httptest.NewServer(h.Handler())
	defer hub.Close()
	sub := newSubscriber(t, "")

	const n = 20
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			resp, err := http.PostForm(hub.URL, subscribeForm(fmt.Sprintf("%s/%d", sub.URL, i), "s"))
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
		})
		wg.Go(func() { publish(t, hub.URL) })
	}
	wg.Wait()
	waitFor(t, "all subscriptions stored", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.subs) == n
	})
	if sum := publish(t, hub.URL); sum["delivered"] != float64(n) {
		t.Fatalf("summary %v", sum)
	}
}
