package main

import (
	"context"
	"encoding/json"
	"errors"
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

func TestSubscribeValidation(t *testing.T) {
	sub := newSubscriber(t)
	form := func(k string, v ...string) string {
		f, _ := url.ParseQuery(subscribeForm(sub.URL+"/x", "s"))
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
		{"callback fragment", "POST", "/", formType, form("hub.callback", sub.URL+"/#f"), http.StatusBadRequest},
		{"callback empty fragment", "POST", "/", formType, form("hub.callback", sub.URL+"/cb#"), http.StatusBadRequest},
		{"callback encoded hash", "POST", "/", formType, form("hub.callback", sub.URL+"/cb?tag=%23x"), http.StatusAccepted},
		{"callback credentials", "POST", "/", formType, form("hub.callback", "http://u:p@127.0.0.1/"), http.StatusBadRequest},
		{"wrong topic", "POST", "/", formType, form("hub.topic", "other"), http.StatusBadRequest},
		{"missing secret", "POST", "/", formType, form("hub.secret"), http.StatusBadRequest},
		{"long secret", "POST", "/", formType, form("hub.secret", strings.Repeat("s", 200)), http.StatusBadRequest},
		{"duplicate callback", "POST", "/", formType, form("hub.callback", sub.URL+"/a", sub.URL+"/b"), http.StatusBadRequest},
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
			waitTasks(t, h)
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
	await(t, g.atHeader, "the acceptance header")
	close(g.proceed)
	if !await(t, flushedFirst, "the verification request") {
		t.Fatal("verification started before the acceptance was flushed")
	}
	waitTasks(t, h)
}

func TestNotDeliveredBeforeVerification(t *testing.T) {
	h, _ := newHub(t)
	sub := newSubscriber(t)
	held, release := newRelease(t)
	sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
		hold(r, held)
		echoChallenge(w, r)
	})
	if code := subscribe(h, sub.URL+"/cb", "secret"); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	if sum := publish(t, h); sum.Selected != 0 {
		t.Fatalf("delivered before verification: %+v", sum)
	}
	release()
	waitTasks(t, h)
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

	raw := await(t, queries, "the verification query")
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
	for _, d := range []delivery{da, db} {
		if d.method != http.MethodPost || d.contentType != "application/json" {
			t.Fatalf("delivery sent as %s with Content-Type %q", d.method, d.contentType)
		}
	}
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
	h.exchangeTimeout = 50 * time.Millisecond

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
		l.waitFor(t, "failure=canceled")
	})

	t.Run("broadcast budget exhausted", func(t *testing.T) {
		h, l, first, second := setup(t)
		h.broadcastBudget = 50 * time.Millisecond
		first.setDeliver(func(r *http.Request) { <-r.Context().Done() })
		check(t, publish(t, h), second)
		l.waitFor(t, "failure=timeout")
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
		l.waitFor(t, "msg=verified subscription=3")
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
		if h.reserveVerification(&older) != nil || h.reserveVerification(&newer) != nil {
			t.Fatal("admission refused")
		}
		if !newerOK {
			sub.setVerify(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
		}
		h.verify(newer)
		sub.setVerify(echoChallenge)
		h.verify(older)

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
	entered := make(chan struct{})
	held, release := newRelease(t)
	x.setVerify(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		hold(r, held)
		echoChallenge(w, r)
	})
	subscribe(h, x.URL+"/cb", "old")
	await(t, entered, "the old verification")
	x.setVerify(echoChallenge)
	subscribe(h, x.URL+"/cb", "new")
	l.waitFor(t, "msg=verified subscription=2")

	c.advance(lease)
	subscribe(h, y.URL+"/cb", "y")
	l.waitFor(t, "msg=verified subscription=3")
	release()
	waitTasks(t, h)
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
		held, release := newRelease(t)
		var calls atomic.Int32
		sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			hold(r, held)
			echoChallenge(w, r)
		})
		for i, want := range []int{http.StatusAccepted, http.StatusAccepted, http.StatusServiceUnavailable} {
			if code := subscribe(h, sub.URL+"/cb"+string(rune('a'+i)), "s"); code != want {
				t.Fatalf("subscribe %d: status %d, want %d", i, code, want)
			}
		}
		release()
		waitTasks(t, h)
		if calls.Load() != 2 {
			t.Fatalf("%d verifications started, want 2", calls.Load())
		}
		if code := subscribe(h, sub.URL+"/cbz", "s"); code != http.StatusAccepted {
			t.Fatalf("capacity not released: status %d", code)
		}
		waitTasks(t, h)
	})

	t.Run("subscriptions", func(t *testing.T) {
		h, _ := newHub(t)
		h.maxCallbacks = 2
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
	t.Cleanup(func() { pw.Close() })
	within(t, "the handler reading the body", func() { io.WriteString(pw, form[:4]) })
	h.stopAdmission()
	within(t, "the handler reading the body", func() { io.WriteString(pw, form[4:]) })
	pw.Close()
	await(t, done, "the in-flight registration")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("in-flight registration: status %d", rec.Code)
	}
	if code := subscribe(h, sub.URL+"/cb", "s"); code != http.StatusServiceUnavailable {
		t.Fatalf("new registration: status %d", code)
	}
	if rec := serve(h, http.MethodPost, "/publish", "", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("new publish: status %d", rec.Code)
	}
	waitTasks(t, h)
	if verifications.Load() != 0 {
		t.Fatal("a verification started after admission stopped")
	}
}

func TestDiagnostics(t *testing.T) {
	const token = "tok3n-in-query"
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	cases := []struct {
		name  string
		want  func(challenge string) string
		reply handlerFunc
	}{
		{"challenge mismatch", func(c string) string {
			return fmt.Sprintf("failure=\"challenge mismatch: got 4 bytes, want %d\"", len(c))
		}, func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "nope") }},
		{"unexpected status", func(string) string { return "failure=\"unexpected status 500\"" }, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"transport failure", func(string) string { return "failure=\"transport failure\"" }, nil},
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
			var challenge string
			if tc.reply != nil {
				challenge = await(t, challenges, "the verification request")
			}
			l.waitFor(t, tc.want(challenge))
			out := l.String()
			if strings.Contains(out, token) || strings.Contains(out, base) {
				t.Fatalf("log exposes the callback URL:\n%s", out)
			}
			if challenge != "" && strings.Contains(out, challenge) {
				t.Fatalf("log exposes the challenge:\n%s", out)
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
	waitTasks(t, h)
	if sum := publish(t, h); sum.Selected != 1 || sum.Acknowledged != 1 {
		t.Fatalf("summary: %+v", sum)
	}
}

// TestCapacityCountsDistinctCallbacks holds a renewal of a stored callback
// open: it must not count twice, and each verification that ends releases
// only its own callback's reservation.
func TestCapacityCountsDistinctCallbacks(t *testing.T) {
	h, l := newHub(t)
	h.maxCallbacks = 2
	sub := newSubscriber(t)
	activate(t, h, sub.URL+"/a", "s")
	heldA, releaseA := newRelease(t)
	heldB, releaseB := newRelease(t)
	sub.setVerify(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			hold(r, heldA)
			echoChallenge(w, r)
		case "/b":
			hold(r, heldB)
			w.WriteHeader(http.StatusNotFound)
		default:
			echoChallenge(w, r)
		}
	})
	expect := func(callback string, want int) {
		t.Helper()
		if code := subscribe(h, sub.URL+callback, "s"); code != want {
			t.Fatalf("subscribe %s: status %d, want %d", callback, code, want)
		}
	}

	expect("/a", http.StatusAccepted)
	expect("/b", http.StatusAccepted)
	expect("/c", http.StatusServiceUnavailable)
	releaseA()
	l.waitFor(t, "msg=verified subscription=2")
	expect("/c", http.StatusServiceUnavailable)
	releaseB()
	l.waitFor(t, "subscription=3 failure=\"unexpected status 404\"")
	expect("/c", http.StatusAccepted)
}

// TestBroadcastStartRotates puts two slow recipients ahead of a healthy one.
// The budget runs out on the second slow attempt, which here is emulated by
// canceling the publish when it starts, so the healthy recipient misses the
// first broadcast. The next broadcast starts one place later and reaches it.
func TestBroadcastStartRotates(t *testing.T) {
	h, _ := newHub(t)
	h.exchangeTimeout = 20 * time.Millisecond
	slow1, slow2, healthy := newSubscriber(t), newSubscriber(t), newSubscriber(t)
	activate(t, h, slow1.URL+"/1", "s")
	activate(t, h, slow2.URL+"/2", "s")
	activate(t, h, healthy.URL+"/ok", "s")

	broadcast := func() (summary, int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var slowStarted atomic.Int32
		stall := func(r *http.Request) {
			if slowStarted.Add(1) == 2 {
				cancel()
			}
			<-r.Context().Done()
		}
		slow1.setDeliver(stall)
		slow2.setDeliver(stall)
		return publishWith(ctx, t, h), len(healthy.received())
	}
	if sum, got := broadcast(); got != 0 || sum.NotAttempted != 1 {
		t.Fatalf("first broadcast: %+v, healthy received %d", sum, got)
	}
	if sum, got := broadcast(); got != 1 || sum.Acknowledged != 1 {
		t.Fatalf("second broadcast: %+v, healthy received %d", sum, got)
	}
}

// TestPublishLimit fills the publish slots; one more publish is refused
// before it generates an event, and the slot frees when a publish ends.
func TestPublishLimit(t *testing.T) {
	h, l := newHub(t)
	h.maxPublishing = 1
	sub := newSubscriber(t)
	activate(t, h, sub.URL+"/cb", "s")
	delivering := make(chan struct{})
	held, release := newRelease(t)
	var once sync.Once
	sub.setDeliver(func(r *http.Request) {
		once.Do(func() { close(delivering) })
		hold(r, held)
	})

	first := publishAsync(context.Background(), h)
	await(t, delivering, "the first delivery")
	if rec := serve(h, http.MethodPost, "/publish", "", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("publish over the limit: status %d", rec.Code)
	}
	release()
	rec := await(t, first, "the first publish")
	decodeSummary(t, rec.Code, rec.Body.Bytes())
	if n := strings.Count(l.String(), "msg=published"); n != 1 || len(sub.received()) != 1 {
		t.Fatalf("refused publish generated an event: %d published, %d delivered", n, len(sub.received()))
	}
	if sum := publish(t, h); sum.Acknowledged != 1 {
		t.Fatalf("slot not released: %+v", sum)
	}
}

type unflushableWriter struct{ *httptest.ResponseRecorder }

func (unflushableWriter) FlushError() error { return errors.New("connection gone") }

// TestAcceptanceFlushFailure: when the 202 cannot be flushed the hub logs it
// and still verifies, then releases the reservation as usual.
func TestAcceptanceFlushFailure(t *testing.T) {
	h, l := newHub(t)
	sub := newSubscriber(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(subscribeForm(sub.URL+"/cb", "s")))
	req.Header.Set("Content-Type", formType)
	w := unflushableWriter{httptest.NewRecorder()}
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	l.waitFor(t, "msg=\"acceptance not flushed\" subscription=1")
	l.waitFor(t, "msg=verified subscription=1")
	waitTasks(t, h)
	h.mu.Lock()
	pending, verifying := h.verifications, len(h.verifying)
	h.mu.Unlock()
	if pending != 0 || verifying != 0 {
		t.Fatalf("reservation not released: pending %d, verifying %d", pending, verifying)
	}
}
