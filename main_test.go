package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T, h *Hub, grace time.Duration) (url string, stop context.CancelFunc, stopped <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- run(ctx, ln, h, grace) }()
	t.Cleanup(cancel)
	return "http://" + ln.Addr().String(), cancel, errc
}

// TestShutdownDrainsInFlightWork stops the server while a publish is blocked
// on a subscriber and an accepted verification is outstanding. run must
// finish both before it returns, and the publisher must get its summary.
func TestShutdownDrainsInFlightWork(t *testing.T) {
	h, l := newHub(t)
	x, y := newSubscriber(t), newSubscriber(t)
	activate(t, h, x.URL+"/x", "x")
	delivering, verifying, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	x.setDeliver(func(*http.Request) {
		close(delivering)
		<-release
	})
	y.setVerify(func(w http.ResponseWriter, r *http.Request) {
		close(verifying)
		<-release
		echoChallenge(w, r)
	})
	base, stop, stopped := start(t, h, time.Minute)

	resp, err := http.Post(base, formType, strings.NewReader(subscribeForm(y.URL+"/y", "y")))
	if err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("subscribe: %v %v", resp, err)
	}
	resp.Body.Close()
	<-verifying
	published := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Post(base+"/publish", "", nil) //nolint:bodyclose // closed by the receiver
		if err != nil {
			t.Errorf("publish: %v", err)
		}
		published <- resp
	}()
	<-delivering

	stop()
	l.waitFor("msg=draining")
	select {
	case err := <-stopped:
		t.Fatalf("run returned with work in flight: %v", err)
	default:
	}
	close(release)

	resp = <-published
	if resp == nil {
		t.FailNow()
	}
	defer resp.Body.Close()
	var sum summary
	if err := json.NewDecoder(resp.Body).Decode(&sum); err != nil || sum.Acknowledged != 1 {
		t.Fatalf("publish summary %+v, %v", sum, err)
	}
	if err := <-stopped; err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, ok := h.subs[y.URL+"/y"]; !ok {
		t.Fatal("verification accepted before shutdown was not completed")
	}
}

// TestShutdownGraceExpiry holds a delivery and a verification open past the
// grace period. run must cancel them, wait for both to unwind, and report it.
func TestShutdownGraceExpiry(t *testing.T) {
	h, l := newHub(t)
	x, y := newSubscriber(t), newSubscriber(t)
	activate(t, h, x.URL+"/x", "x")
	delivering, verifying := make(chan struct{}), make(chan struct{})
	x.setDeliver(func(r *http.Request) {
		close(delivering)
		<-r.Context().Done()
	})
	y.setVerify(func(_ http.ResponseWriter, r *http.Request) {
		close(verifying)
		<-r.Context().Done()
	})
	base, stop, stopped := start(t, h, 50*time.Millisecond)

	resp, err := http.Post(base, formType, strings.NewReader(subscribeForm(y.URL+"/y", "y")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	<-verifying
	go func() {
		if resp, err := http.Post(base+"/publish", "", nil); err == nil {
			resp.Body.Close()
		}
	}()
	<-delivering

	stop()
	if err := <-stopped; err == nil || !strings.Contains(err.Error(), "grace period expired") {
		t.Fatalf("run: %v", err)
	}
	h.mu.Lock()
	pending := h.pending
	h.mu.Unlock()
	if pending != 0 {
		t.Fatalf("%d verifications still outstanding after run returned", pending)
	}
	l.waitFor("failure=canceled")
}
