package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type delivery struct {
	query     string
	signature string
	body      []byte
}

type handlerFunc = func(w http.ResponseWriter, r *http.Request)

// subscriber is a fake callback. Its hooks are guarded by mu because tests
// swap them while the server is running.
type subscriber struct {
	*httptest.Server

	mu         sync.Mutex
	onVerify   handlerFunc
	onDeliver  func()
	deliveries []delivery
}

func newSubscriber(t *testing.T) *subscriber {
	s := &subscriber{onVerify: echoChallenge, onDeliver: func() {}}
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
		s.deliveries = append(s.deliveries, delivery{r.URL.RawQuery, r.Header.Get("X-Hub-Signature"), body})
		s.mu.Unlock()
		onDeliver()
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *subscriber) setVerify(f handlerFunc) {
	s.mu.Lock()
	s.onVerify = f
	s.mu.Unlock()
}

func (s *subscriber) setDeliver(f func()) {
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

func serve(h *Hub, method, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	return rec
}

func subscribe(h *Hub, callback, secret string) int {
	form := url.Values{
		"hub.mode":     {"subscribe"},
		"hub.callback": {callback},
		"hub.topic":    {topic},
		"hub.secret":   {secret},
	}
	return serve(h, http.MethodPost, "/", "application/x-www-form-urlencoded; charset=UTF-8", form.Encode()).Code
}

func publish(t *testing.T, h *Hub) summary {
	t.Helper()
	rec := serve(h, http.MethodPost, "/publish", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: status %d", rec.Code)
	}
	var sum summary
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	return sum
}

// validMAC recomputes the signature independently of the hub's code.
func validMAC(secret string, d delivery) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(d.body)
	return d.signature == "sha256="+hex.EncodeToString(mac.Sum(nil))
}

func TestSubscribeValidation(t *testing.T) {
	form := func(k string, v ...string) string {
		f := url.Values{
			"hub.mode": {"subscribe"}, "hub.callback": {"http://cb.test/x"},
			"hub.topic": {topic}, "hub.secret": {"s"},
		}
		if k != "" {
			f[k] = v
		}
		return f.Encode()
	}
	const formType = "application/x-www-form-urlencoded"
	cases := []struct {
		name, method, path, ctype, body string
		want                            int
	}{
		{"valid", "POST", "/", formType, form(""), http.StatusAccepted},
		{"valid lease", "POST", "/", formType, form("hub.lease_seconds", "60"), http.StatusAccepted},
		{"unsubscribe", "POST", "/", formType, form("hub.mode", "unsubscribe"), http.StatusBadRequest},
		{"relative callback", "POST", "/", formType, form("hub.callback", "/cb"), http.StatusBadRequest},
		{"callback fragment", "POST", "/", formType, form("hub.callback", "http://cb.test/#f"), http.StatusBadRequest},
		{"callback credentials", "POST", "/", formType, form("hub.callback", "http://u:p@cb.test/"), http.StatusBadRequest},
		{"wrong topic", "POST", "/", formType, form("hub.topic", "other"), http.StatusBadRequest},
		{"missing secret", "POST", "/", formType, form("hub.secret"), http.StatusBadRequest},
		{"long secret", "POST", "/", formType, form("hub.secret", strings.Repeat("s", 200)), http.StatusBadRequest},
		{"duplicate callback", "POST", "/", formType, form("hub.callback", "http://a.test/", "http://b.test/"), http.StatusBadRequest},
		{"bad lease", "POST", "/", formType, form("hub.lease_seconds", "-1"), http.StatusBadRequest},
		{"json body", "POST", "/", "application/json", "{}", http.StatusUnsupportedMediaType},
		{"oversized", "POST", "/", formType, "hub.secret=" + strings.Repeat("s", maxFormBytes), http.StatusRequestEntityTooLarge},
		{"wrong method", "GET", "/", "", "", http.StatusMethodNotAllowed},
		{"publish wrong method", "GET", "/publish", "", "", http.StatusMethodNotAllowed},
		{"unknown path", "POST", "/nope", "", "", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHub(time.Second)
			if rec := serve(h, tc.method, tc.path, tc.ctype, tc.body); rec.Code != tc.want {
				t.Errorf("status %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
			h.pending.Wait()
		})
	}
}

func TestAcceptedBeforeVerification(t *testing.T) {
	h := NewHub(5 * time.Second)
	sub := newSubscriber(t)
	release := make(chan struct{})
	sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
		<-release
		echoChallenge(w, r)
	})

	if code := subscribe(h, sub.URL+"/cb", "secret"); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	if sum := publish(t, h); sum.Selected != 0 {
		t.Fatalf("delivered before verification: %+v", sum)
	}
	close(release)
	h.pending.Wait()
	if sum := publish(t, h); sum.Acknowledged != 1 {
		t.Fatalf("not delivered after verification: %+v", sum)
	}
}

func TestFailedVerificationKeepsPreviousRecord(t *testing.T) {
	challenge := func(r *http.Request) string { return r.URL.Query().Get("hub.challenge") }
	cases := map[string]handlerFunc{
		"newline suffix": func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, challenge(r)+"\n") },
		"quoted":         func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `"`+challenge(r)+`"`) },
		"wrong":          func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "nope") },
		"non-2xx": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, challenge(r))
		},
		"redirect to success": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ok" {
				io.WriteString(w, challenge(r))
				return
			}
			http.Redirect(w, r, "/ok?"+r.URL.RawQuery, http.StatusFound)
		},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			h := NewHub(5 * time.Second)
			sub := newSubscriber(t)
			callback := sub.URL + "/cb"
			subscribe(h, callback, "first")
			h.pending.Wait()
			before := h.subs[callback]

			sub.setVerify(reply)
			subscribe(h, callback, "second")
			h.pending.Wait()

			after := h.subs[callback]
			if string(after.secret) != "first" || !after.expiresAt.Equal(before.expiresAt) {
				t.Fatalf("failed verification replaced the record: secret %q", after.secret)
			}
		})
	}
}

func TestCallbackQueryPreserved(t *testing.T) {
	h := NewHub(5 * time.Second)
	sub := newSubscriber(t)
	queries := make(chan url.Values, 1)
	sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.Query()
		echoChallenge(w, r)
	})
	subscribe(h, sub.URL+"/cb?id=7&x=a%20b", "secret")
	h.pending.Wait()

	q := <-queries
	if q.Get("id") != "7" || q.Get("x") != "a b" || q.Get("hub.mode") != "subscribe" ||
		q.Get("hub.topic") != topic || q.Get("hub.lease_seconds") != "86400" || q.Get("hub.challenge") == "" {
		t.Fatalf("verification query: %v", q)
	}
	publish(t, h)
	if got := sub.received(); len(got) != 1 || got[0].query != "id=7&x=a%20b" {
		t.Fatalf("delivery query: %+v", got)
	}
}

func TestBroadcastSignsPerSubscriber(t *testing.T) {
	h := NewHub(5 * time.Second)
	a, b := newSubscriber(t), newSubscriber(t)
	subscribe(h, a.URL+"/a", "secret-a")
	subscribe(h, b.URL+"/b", "secret-b")
	h.pending.Wait()

	sum := publish(t, h)
	if sum.Selected != 2 || sum.Attempted != 2 || sum.Acknowledged != 2 || sum.Failed != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	da, db := a.received()[0], b.received()[0]
	if string(da.body) != string(db.body) {
		t.Fatal("subscribers received different payloads")
	}
	if !json.Valid(da.body) || !strings.Contains(string(da.body), sum.EventID) {
		t.Fatalf("payload: %s", da.body)
	}
	if !validMAC("secret-a", da) || !validMAC("secret-b", db) {
		t.Fatal("signature does not validate with the subscriber's own secret")
	}
	if validMAC("secret-b", da) || validMAC("secret-a", db) {
		t.Fatal("signature validates with another subscriber's secret")
	}
	da.body = append(da.body, ' ')
	if validMAC("secret-a", da) {
		t.Fatal("signature validates a tampered body")
	}
}

func TestBroadcastContinuesAfterFailure(t *testing.T) {
	h := NewHub(200 * time.Millisecond)
	slow, healthy := newSubscriber(t), newSubscriber(t)
	subscribe(h, slow.URL+"/slow", "a")
	h.pending.Wait()
	subscribe(h, healthy.URL+"/ok", "b")
	h.pending.Wait()

	slow.setDeliver(func() { time.Sleep(time.Second) })
	sum := publish(t, h)
	if sum.Attempted != 2 || sum.Failed != 1 || sum.Acknowledged != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	if len(healthy.received()) != 1 {
		t.Fatal("healthy subscriber was not attempted")
	}
}

// TestNewestVerifiedRevisionWins completes two verifications for the same
// callback in the reverse order of their acceptance.
func TestNewestVerifiedRevisionWins(t *testing.T) {
	run := func(t *testing.T, newerOK bool, want string) {
		h := NewHub(5 * time.Second)
		sub := newSubscriber(t)
		callback := sub.URL + "/cb"
		older := subscription{callback: callback, secret: []byte("older"), revision: 1}
		newer := subscription{callback: callback, secret: []byte("newer"), revision: 2}

		if !newerOK {
			sub.setVerify(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
		}
		h.verify(newer)
		sub.setVerify(echoChallenge)
		h.verify(older)

		if got := string(h.subs[callback].secret); got != want {
			t.Fatalf("active secret %q, want %q", got, want)
		}
	}
	t.Run("late older success does not overwrite", func(t *testing.T) { run(t, true, "newer") })
	t.Run("older succeeds when newer fails", func(t *testing.T) { run(t, false, "older") })
}

type clock struct{ ns atomic.Int64 }

func (c *clock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *clock) advance(d time.Duration) { c.ns.Add(int64(d)) }

func TestExpiry(t *testing.T) {
	t.Run("empty registry", func(t *testing.T) {
		if sum := publish(t, NewHub(time.Second)); sum.Selected != 0 || sum.Attempted != 0 {
			t.Fatalf("summary: %+v", sum)
		}
	})

	t.Run("expired before broadcast", func(t *testing.T) {
		h, c := NewHub(5*time.Second), &clock{}
		h.now = c.now
		sub := newSubscriber(t)
		subscribe(h, sub.URL+"/cb", "s")
		h.pending.Wait()
		c.advance(leaseSeconds * time.Second)
		if sum := publish(t, h); sum.Selected != 0 || len(sub.received()) != 0 {
			t.Fatalf("summary: %+v", sum)
		}
	})

	t.Run("expires during broadcast", func(t *testing.T) {
		h, c := NewHub(5*time.Second), &clock{}
		h.now = c.now
		first, second := newSubscriber(t), newSubscriber(t)
		subscribe(h, first.URL+"/cb", "s")
		h.pending.Wait()
		subscribe(h, second.URL+"/cb", "s")
		h.pending.Wait()

		first.setDeliver(func() { c.advance(leaseSeconds * time.Second) })
		sum := publish(t, h)
		if sum.Selected != 2 || sum.Attempted != 1 || sum.SkippedExpired != 1 || len(second.received()) != 0 {
			t.Fatalf("summary: %+v", sum)
		}
	})
}

func TestConcurrentSubscribeAndPublish(t *testing.T) {
	h := NewHub(5 * time.Second)
	sub := newSubscriber(t)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() { subscribe(h, sub.URL+"/cb", "secret") })
		if i%4 == 0 {
			wg.Go(func() { serve(h, http.MethodPost, "/publish", "", "") })
		}
	}
	wg.Wait()
	h.pending.Wait()
	if sum := publish(t, h); sum.Selected != 1 || sum.Acknowledged != 1 {
		t.Fatalf("summary: %+v", sum)
	}
}
