package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// failAfter bounds every wait in these tests. Channels establish ordering;
// the deadline only turns a regression into a failure instead of a hang.
const failAfter = 5 * time.Second

func await[T any](t *testing.T, c <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(failAfter):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	await(t, done, what)
}

func waitTasks(t *testing.T, h *Hub) {
	t.Helper()
	within(t, "admitted hub tasks", h.tasks.Wait)
}

// newRelease returns a channel that held fake handlers wait on and a
// close-once release. The release is also a cleanup; registered after the
// fake servers, it runs before they close, since cleanups run last-in first.
func newRelease(t *testing.T) (<-chan struct{}, func()) {
	ch := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	return ch, release
}

// hold blocks a fake handler until the test releases it or the request ends.
func hold(r *http.Request, release <-chan struct{}) {
	select {
	case <-release:
	case <-r.Context().Done():
	}
}

type delivery struct {
	method, contentType, query, signature string
	body                                  []byte
}

type handlerFunc = func(w http.ResponseWriter, r *http.Request)

// subscriber is a fake callback. Its hooks are guarded by mu because tests
// swap them while the server is running.
type subscriber struct {
	*httptest.Server

	mu         sync.Mutex
	onVerify   handlerFunc
	onDeliver  func(r *http.Request)
	deliveries []delivery
}

func newSubscriber(t *testing.T) *subscriber {
	s := &subscriber{onVerify: echoChallenge, onDeliver: func(*http.Request) {}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		onVerify, onDeliver := s.onVerify, s.onDeliver
		s.mu.Unlock()
		if r.Method == http.MethodGet {
			onVerify(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.deliveries = append(s.deliveries, delivery{r.Method, r.Header.Get("Content-Type"), r.URL.RawQuery, r.Header.Get("X-Hub-Signature"), body})
		s.mu.Unlock()
		onDeliver(r)
	}))
	// Dropping connections first ends the request context of any handler
	// still held, so Close cannot wait on it.
	t.Cleanup(func() {
		s.CloseClientConnections()
		s.Close()
	})
	return s
}

func (s *subscriber) setVerify(f handlerFunc) {
	s.mu.Lock()
	s.onVerify = f
	s.mu.Unlock()
}

func (s *subscriber) setDeliver(f func(r *http.Request)) {
	s.mu.Lock()
	s.onDeliver = f
	s.mu.Unlock()
}

func (s *subscriber) received() []delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]delivery(nil), s.deliveries...)
}

func echoChallenge(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, r.URL.Query().Get("hub.challenge"))
}

// logs collects hub output and lets tests wait for a line without polling.
type logs struct {
	mu   sync.Mutex
	cond *sync.Cond
	text string
}

func newLogs() *logs {
	l := &logs{}
	l.cond = sync.NewCond(&l.mu)
	return l
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.text += string(p)
	l.mu.Unlock()
	l.cond.Broadcast()
	return len(p), nil
}

func (l *logs) waitFor(t *testing.T, s string) {
	t.Helper()
	expired := false
	timer := time.AfterFunc(failAfter, func() {
		l.mu.Lock()
		expired = true
		l.mu.Unlock()
		l.cond.Broadcast()
	})
	defer timer.Stop()
	l.mu.Lock()
	defer l.mu.Unlock()
	for !strings.Contains(l.text, s) {
		if expired {
			t.Fatalf("log line %q not seen; log so far:\n%s", s, l.text)
		}
		l.cond.Wait()
	}
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text
}

// loopbackOnly keeps the tests hermetic: every callback is a local fake, so
// any other destination is a test bug, reported instead of contacted.
type loopbackOnly struct{ t *testing.T }

func (l loopbackOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if ip := net.ParseIP(r.URL.Hostname()); ip == nil || !ip.IsLoopback() {
		l.t.Errorf("unexpected outbound request to %s", r.URL.Host)
		return nil, errors.New("unexpected outbound request")
	}
	return http.DefaultTransport.RoundTrip(r)
}

// newHub logs the way the program does. Its cleanup is registered first, so
// it runs last: after held handlers are released and fake servers closed.
func newHub(t *testing.T) (*Hub, *logs) {
	h, l := NewHub(), newLogs()
	h.log = newLogger(l)
	h.client.Transport = loopbackOnly{t}
	t.Cleanup(func() { waitTasks(t, h) })
	return h, l
}

func serve(h *Hub, method, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func subscribeForm(callback, secret string) string {
	return url.Values{
		"hub.mode": {"subscribe"}, "hub.callback": {callback}, "hub.topic": {topic}, "hub.secret": {secret},
	}.Encode()
}

func subscribe(h *Hub, callback, secret string) int {
	return serve(h, http.MethodPost, "/", formType+"; charset=UTF-8", subscribeForm(callback, secret)).Code
}

// activate subscribes and waits for the verification to finish.
func activate(t *testing.T, h *Hub, callback, secret string) {
	t.Helper()
	if code := subscribe(h, callback, secret); code != http.StatusAccepted {
		t.Fatalf("subscribe: status %d", code)
	}
	waitTasks(t, h)
}

func publishAsync(ctx context.Context, h *Hub) <-chan *httptest.ResponseRecorder {
	c := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodPost, "/publish", nil))
		c <- rec
	}()
	return c
}

// decodeSummary checks a publish response and the summary invariants.
func decodeSummary(t *testing.T, code int, body []byte) summary {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("publish: status %d: %s", code, body)
	}
	var sum summary
	if err := json.Unmarshal(body, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Selected != sum.Attempted+sum.SkippedExpired+sum.NotAttempted || sum.Attempted != sum.Acknowledged+sum.Failed {
		t.Fatalf("summary invariants violated: %+v", sum)
	}
	return sum
}

func publishWith(ctx context.Context, t *testing.T, h *Hub) summary {
	t.Helper()
	rec := await(t, publishAsync(ctx, h), "publish")
	return decodeSummary(t, rec.Code, rec.Body.Bytes())
}

func publish(t *testing.T, h *Hub) summary { return publishWith(context.Background(), t, h) }

// validMAC recomputes the signature independently of the hub's code.
func validMAC(secret string, d delivery) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(d.body)
	return d.signature == "sha256="+hex.EncodeToString(mac.Sum(nil))
}
