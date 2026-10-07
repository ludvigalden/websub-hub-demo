package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
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
		s.deliveries = append(s.deliveries, delivery{r.URL.RawQuery, r.Header.Get("X-Hub-Signature"), body})
		s.mu.Unlock()
		onDeliver(r)
	}))
	t.Cleanup(s.Close)
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

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.text += string(p)
	l.mu.Unlock()
	l.cond.Broadcast()
	return len(p), nil
}

func (l *logs) waitFor(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for !strings.Contains(l.text, s) {
		l.cond.Wait()
	}
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text
}

func newHub(t *testing.T) (*Hub, *logs) {
	h, l := NewHub(), &logs{}
	l.cond = sync.NewCond(&l.mu)
	h.log = slog.New(slog.NewTextHandler(l, nil))
	t.Cleanup(h.abort)
	return h, l
}

func closeAdmission(h *Hub) {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
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
	h.tasks.Wait()
}

func publishWith(ctx context.Context, t *testing.T, h *Hub) summary {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodPost, "/publish", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: status %d", rec.Code)
	}
	var sum summary
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Selected != sum.Attempted+sum.SkippedExpired+sum.NotAttempted || sum.Attempted != sum.Acknowledged+sum.Failed {
		t.Fatalf("summary invariants violated: %+v", sum)
	}
	return sum
}

func publish(t *testing.T, h *Hub) summary { return publishWith(context.Background(), t, h) }

// validMAC recomputes the signature independently of the hub's code.
func validMAC(secret string, d delivery) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(d.body)
	return d.signature == "sha256="+hex.EncodeToString(mac.Sum(nil))
}

func TestSubscribeValidation(t *testing.T) {
	form := func(k string, v ...string) string {
		f, _ := url.ParseQuery(subscribeForm("http://cb.test/x", "s"))
		if k != "" {
			f[k] = v
		}
		return f.Encode()
	}
	cases := []struct {
		name, method, path, ctype, body string
		want                            int
	}{
		{"valid", "POST", "/", formType, form(""), http.StatusAccepted},
		{"valid lease", "POST", "/", formType, form("hub.lease_seconds", "60"), http.StatusAccepted},
		{"unsubscribe", "POST", "/", formType, form("hub.mode", "unsubscribe"), http.StatusBadRequest},
		{"relative callback", "POST", "/", formType, form("hub.callback", "/cb"), http.StatusBadRequest},
		{"hostless callback", "POST", "/", formType, form("hub.callback", "http://:8080/cb"), http.StatusBadRequest},
		{"empty host callback", "POST", "/", formType, form("hub.callback", "http:///cb"), http.StatusBadRequest},
		{"callback fragment", "POST", "/", formType, form("hub.callback", "http://cb.test/#f"), http.StatusBadRequest},
		{"callback credentials", "POST", "/", formType, form("hub.callback", "http://u:p@cb.test/"), http.StatusBadRequest},
		{"wrong topic", "POST", "/", formType, form("hub.topic", "other"), http.StatusBadRequest},
		{"missing secret", "POST", "/", formType, form("hub.secret"), http.StatusBadRequest},
		{"long secret", "POST", "/", formType, form("hub.secret", strings.Repeat("s", 200)), http.StatusBadRequest},
		{"duplicate callback", "POST", "/", formType, form("hub.callback", "http://a.test/", "http://b.test/"), http.StatusBadRequest},
		{"negative lease", "POST", "/", formType, form("hub.lease_seconds", "-1"), http.StatusBadRequest},
		{"zero lease", "POST", "/", formType, form("hub.lease_seconds", "0"), http.StatusBadRequest},
		{"empty lease", "POST", "/", formType, form("hub.lease_seconds", ""), http.StatusBadRequest},
		{"json body", "POST", "/", "application/json", "{}", http.StatusUnsupportedMediaType},
		{"oversized", "POST", "/", formType, "hub.secret=" + strings.Repeat("s", maxForm), http.StatusRequestEntityTooLarge},
		{"wrong method", "GET", "/", "", "", http.StatusMethodNotAllowed},
		{"publish wrong method", "GET", "/publish", "", "", http.StatusMethodNotAllowed},
		{"unknown path", "POST", "/nope", "", "", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHub(t)
			if rec := serve(h, tc.method, tc.path, tc.ctype, tc.body); rec.Code != tc.want {
				t.Errorf("status %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
			h.tasks.Wait()
		})
	}
}

// gatedWriter holds the response at WriteHeader until the test lets it go,
// and records whether the response had been flushed.
type gatedWriter struct {
	header            http.Header
	atHeader, proceed chan struct{}
	flushed           chan struct{}
}

func (g *gatedWriter) Header() http.Header         { return g.header }
func (g *gatedWriter) Write(p []byte) (int, error) { return len(p), nil }
func (g *gatedWriter) Flush()                      { close(g.flushed) }
func (g *gatedWriter) WriteHeader(int) {
	close(g.atHeader)
	<-g.proceed
}

func TestAcceptanceFlushedBeforeVerification(t *testing.T) {
	h, _ := newHub(t)
	sub := newSubscriber(t)
	g := &gatedWriter{http.Header{}, make(chan struct{}), make(chan struct{}), make(chan struct{})}
	flushedFirst := make(chan bool, 1)
	sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-g.flushed:
			flushedFirst <- true
		default:
			flushedFirst <- false
		}
		echoChallenge(w, r)
	})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(subscribeForm(sub.URL+"/cb", "s")))
	req.Header.Set("Content-Type", formType)
	go h.ServeHTTP(g, req)
	<-g.atHeader
	close(g.proceed)
	if !<-flushedFirst {
		t.Fatal("verification started before the acceptance was flushed")
	}
	h.tasks.Wait()
}

func TestNotDeliveredBeforeVerification(t *testing.T) {
	h, _ := newHub(t)
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
	h.tasks.Wait()
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
			h, _ := newHub(t)
			sub := newSubscriber(t)
			callback := sub.URL + "/cb"
			activate(t, h, callback, "first")
			before := h.subs[callback]

			sub.setVerify(reply)
			activate(t, h, callback, "second")

			after := h.subs[callback]
			if after.secret != "first" || !after.expiresAt.Equal(before.expiresAt) {
				t.Fatalf("failed verification replaced the record: secret %q", after.secret)
			}
		})
	}
}

func TestCallbackQueryPreserved(t *testing.T) {
	h, _ := newHub(t)
	sub := newSubscriber(t)
	queries := make(chan string, 1)
	sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.RawQuery
		echoChallenge(w, r)
	})
	activate(t, h, sub.URL+"/cb?id=7&x=a%20b&hub.mode=keep", "secret")

	raw := <-queries
	q, _ := url.ParseQuery(raw)
	if !strings.HasPrefix(raw, "id=7&x=a%20b&hub.mode=keep&") || q.Get("hub.topic") != topic ||
		q.Get("hub.lease_seconds") != "86400" || q.Get("hub.challenge") == "" || len(q["hub.mode"]) != 2 {
		t.Fatalf("verification query: %s", raw)
	}
	publish(t, h)
	if got := sub.received(); len(got) != 1 || got[0].query != "id=7&x=a%20b&hub.mode=keep" {
		t.Fatalf("delivery query: %+v", got)
	}
}

func TestBroadcastSignsPerSubscriber(t *testing.T) {
	h, _ := newHub(t)
	a, b := newSubscriber(t), newSubscriber(t)
	activate(t, h, a.URL+"/a", "secret-a")
	activate(t, h, b.URL+"/b", "secret-b")

	sum := publish(t, h)
	if sum.Selected != 2 || sum.Acknowledged != 2 {
		t.Fatalf("summary: %+v", sum)
	}
	da, db := a.received()[0], b.received()[0]
	var ev event
	if string(da.body) != string(db.body) || json.Unmarshal(da.body, &ev) != nil || ev.EventID != sum.EventID {
		t.Fatalf("payloads differ or lack the event id: %s / %s", da.body, db.body)
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

func TestBroadcastContinuesAfterTimeout(t *testing.T) {
	h, _ := newHub(t)
	slow, healthy := newSubscriber(t), newSubscriber(t)
	activate(t, h, slow.URL+"/slow", "a")
	activate(t, h, healthy.URL+"/ok", "b")
	h.timeout = 50 * time.Millisecond

	slow.setDeliver(func(r *http.Request) { <-r.Context().Done() })
	if sum := publish(t, h); sum.Attempted != 2 || sum.Failed != 1 || sum.Acknowledged != 1 {
		t.Fatalf("summary: %+v", sum)
	}
}

func TestPublishCancellationAndBudget(t *testing.T) {
	setup := func(t *testing.T) (*Hub, *logs, *subscriber, *subscriber) {
		h, l := newHub(t)
		first, second := newSubscriber(t), newSubscriber(t)
		activate(t, h, first.URL+"/1", "a")
		activate(t, h, second.URL+"/2", "b")
		return h, l, first, second
	}
	want := summary{Selected: 2, Attempted: 1, Failed: 1, NotAttempted: 1}
	check := func(t *testing.T, sum summary, second *subscriber) {
		sum.EventID = ""
		if sum != want || len(second.received()) != 0 {
			t.Fatalf("summary %+v, want %+v", sum, want)
		}
	}

	t.Run("caller canceled before publish", func(t *testing.T) {
		h, _, first, second := setup(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		sum := publishWith(ctx, t, h)
		if sum.Selected != 2 || sum.NotAttempted != 2 || len(first.received())+len(second.received()) != 0 {
			t.Fatalf("summary: %+v", sum)
		}
	})

	t.Run("caller canceled during delivery", func(t *testing.T) {
		h, l, first, second := setup(t)
		ctx, cancel := context.WithCancel(context.Background())
		first.setDeliver(func(r *http.Request) {
			cancel()
			<-r.Context().Done()
		})
		check(t, publishWith(ctx, t, h), second)
		l.waitFor("failure=canceled")
	})

	t.Run("broadcast budget exhausted", func(t *testing.T) {
		h, l, first, second := setup(t)
		h.budget = 50 * time.Millisecond
		first.setDeliver(func(r *http.Request) { <-r.Context().Done() })
		check(t, publish(t, h), second)
		l.waitFor("failure=timeout")
	})
}

// TestRenewalDuringBroadcast renews the second recipient with a new secret
// while the broadcast is blocked on the first; the second delivery must be
// signed with the secret current when it starts.
func TestRenewalDuringBroadcast(t *testing.T) {
	h, l := newHub(t)
	a, b := newSubscriber(t), newSubscriber(t)
	activate(t, h, a.URL+"/a", "a")
	activate(t, h, b.URL+"/b", "old")

	a.setDeliver(func(*http.Request) {
		if code := subscribe(h, b.URL+"/b", "new"); code != http.StatusAccepted {
			t.Errorf("renewal: status %d", code)
		}
		l.waitFor("msg=verified subscription=3")
	})
	if sum := publish(t, h); sum.Acknowledged != 2 {
		t.Fatalf("summary: %+v", sum)
	}
	if got := b.received(); len(got) != 1 || !validMAC("new", got[0]) {
		t.Fatal("delivery after a committed renewal was not signed with the new secret")
	}
}

// TestNewestVerifiedRevisionWins completes two verifications for the same
// callback in the reverse order of their acceptance.
func TestNewestVerifiedRevisionWins(t *testing.T) {
	run := func(t *testing.T, newerOK bool, want string) {
		h, _ := newHub(t)
		sub := newSubscriber(t)
		older := subscription{callback: sub.URL + "/cb", secret: "older"}
		newer := subscription{callback: older.callback, secret: "newer"}
		if h.admit(&older) != nil || h.admit(&newer) != nil {
			t.Fatal("admission refused")
		}
		if !newerOK {
			sub.setVerify(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
		}
		h.verify(h.ctx, newer)
		sub.setVerify(echoChallenge)
		h.verify(h.ctx, older)

		if got := h.subs[older.callback].secret; got != want {
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
		h, _ := newHub(t)
		if sum := publish(t, h); sum.Selected != 0 {
			t.Fatalf("summary: %+v", sum)
		}
	})

	t.Run("expired before broadcast", func(t *testing.T) {
		h, _ := newHub(t)
		c := &clock{}
		h.now = c.now
		sub := newSubscriber(t)
		activate(t, h, sub.URL+"/cb", "s")
		c.advance(lease)
		if sum := publish(t, h); sum.Selected != 0 || len(sub.received()) != 0 {
			t.Fatalf("summary: %+v", sum)
		}
	})

	t.Run("expires during broadcast", func(t *testing.T) {
		h, _ := newHub(t)
		c := &clock{}
		h.now = c.now
		first, second := newSubscriber(t), newSubscriber(t)
		activate(t, h, first.URL+"/cb", "s")
		activate(t, h, second.URL+"/cb", "s")

		first.setDeliver(func(*http.Request) { c.advance(lease) })
		sum := publish(t, h)
		if sum.Selected != 2 || sum.Attempted != 1 || sum.SkippedExpired != 1 || len(second.received()) != 0 {
			t.Fatalf("summary: %+v", sum)
		}
	})
}

// TestRetentionSweep expires a record whose callback still has an older
// verification outstanding. The sweep must keep that record until the older
// verification ends, so the superseded secret cannot come back.
func TestRetentionSweep(t *testing.T) {
	h, l := newHub(t)
	c := &clock{}
	h.now = c.now
	x, y, z := newSubscriber(t), newSubscriber(t), newSubscriber(t)
	entered, release := make(chan struct{}), make(chan struct{})
	x.setVerify(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		echoChallenge(w, r)
	})
	subscribe(h, x.URL+"/cb", "old")
	<-entered
	x.setVerify(echoChallenge)
	subscribe(h, x.URL+"/cb", "new")
	l.waitFor("msg=verified subscription=2")

	c.advance(lease)
	subscribe(h, y.URL+"/cb", "y")
	l.waitFor("msg=verified subscription=3")
	close(release)
	h.tasks.Wait()
	if got := h.subs[x.URL+"/cb"].secret; got != "new" {
		t.Fatalf("record for x has secret %q after overlapping sweep", got)
	}
	if sum := publish(t, h); sum.Selected != 1 || len(x.received()) != 0 {
		t.Fatalf("summary: %+v", sum)
	}

	activate(t, h, z.URL+"/cb", "z")
	if _, kept := h.subs[x.URL+"/cb"]; kept || len(h.subs) != 2 {
		t.Fatalf("expired record not reclaimed: %d stored", len(h.subs))
	}
}

func TestCapacity(t *testing.T) {
	t.Run("verifications", func(t *testing.T) {
		h, _ := newHub(t)
		h.maxVerifying = 2
		sub := newSubscriber(t)
		release := make(chan struct{})
		var calls atomic.Int32
		sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			<-release
			echoChallenge(w, r)
		})
		for i, want := range []int{http.StatusAccepted, http.StatusAccepted, http.StatusServiceUnavailable} {
			if code := subscribe(h, sub.URL+"/cb"+string(rune('a'+i)), "s"); code != want {
				t.Fatalf("subscribe %d: status %d, want %d", i, code, want)
			}
		}
		close(release)
		h.tasks.Wait()
		if calls.Load() != 2 {
			t.Fatalf("%d verifications started, want 2", calls.Load())
		}
		if code := subscribe(h, sub.URL+"/cbz", "s"); code != http.StatusAccepted {
			t.Fatalf("capacity not released: status %d", code)
		}
		h.tasks.Wait()
	})

	t.Run("subscriptions", func(t *testing.T) {
		h, _ := newHub(t)
		h.maxSubs = 2
		sub := newSubscriber(t)
		activate(t, h, sub.URL+"/a", "s")
		activate(t, h, sub.URL+"/b", "s")
		if code := subscribe(h, sub.URL+"/c", "s"); code != http.StatusServiceUnavailable {
			t.Fatalf("third callback: status %d", code)
		}
		activate(t, h, sub.URL+"/a", "renewed")
		if len(h.subs) != 2 || h.subs[sub.URL+"/a"].secret != "renewed" {
			t.Fatal("renewal of a stored callback was refused at capacity")
		}
	})
}

func TestShutdownAdmission(t *testing.T) {
	h, _ := newHub(t)
	sub := newSubscriber(t)
	var verifications atomic.Int32
	sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
		verifications.Add(1)
		echoChallenge(w, r)
	})

	// A registration already inside its handler when admission stops must
	// not start a verification. Writing to the pipe returns only once the
	// handler has read the bytes, so the handler is mid-body when we close.
	form := subscribeForm(sub.URL+"/cb", "s")
	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, "/", pr)
	req.Header.Set("Content-Type", formType)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, req)
		close(done)
	}()
	io.WriteString(pw, form[:4])
	closeAdmission(h)
	io.WriteString(pw, form[4:])
	pw.Close()
	<-done

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("in-flight registration: status %d", rec.Code)
	}
	if code := subscribe(h, sub.URL+"/cb", "s"); code != http.StatusServiceUnavailable {
		t.Fatalf("new registration: status %d", code)
	}
	if rec := serve(h, http.MethodPost, "/publish", "", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("new publish: status %d", rec.Code)
	}
	h.tasks.Wait()
	if verifications.Load() != 0 {
		t.Fatal("a verification started after admission stopped")
	}
}

func TestDiagnostics(t *testing.T) {
	const token = "tok3n-in-query"
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	cases := []struct {
		name, want string
		reply      handlerFunc
	}{
		{"challenge mismatch", "failure=\"challenge mismatch: got 4 bytes, want 26\"", func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "nope")
		}},
		{"unexpected status", "failure=\"unexpected status 500\"", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"transport failure", "failure=\"transport failure\"", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, l := newHub(t)
			sub := newSubscriber(t)
			base, challenges := sub.URL, make(chan string, 1)
			if tc.reply == nil {
				base = dead.URL
			} else {
				sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
					challenges <- r.URL.Query().Get("hub.challenge")
					tc.reply(w, r)
				})
			}
			activate(t, h, base+"/cb?token="+token, "s")
			l.waitFor(tc.want)
			out := l.String()
			if strings.Contains(out, token) || strings.Contains(out, base) {
				t.Fatalf("log exposes the callback URL:\n%s", out)
			}
			select {
			case c := <-challenges:
				if strings.Contains(out, c) {
					t.Fatalf("log exposes the challenge:\n%s", out)
				}
			default:
			}
		})
	}
}

func TestConcurrentSubscribeAndPublish(t *testing.T) {
	h, _ := newHub(t)
	sub := newSubscriber(t)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() { subscribe(h, sub.URL+"/cb", "secret") })
		if i%4 == 0 {
			wg.Go(func() { serve(h, http.MethodPost, "/publish", "", "") })
		}
	}
	wg.Wait()
	h.tasks.Wait()
	if sum := publish(t, h); sum.Selected != 1 || sum.Acknowledged != 1 {
		t.Fatalf("summary: %+v", sum)
	}
}
