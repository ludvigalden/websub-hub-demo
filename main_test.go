package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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

type result struct {
	resp *http.Response
	body []byte
	err  error
}

// post sends a request in the background and collects the whole response.
func post(t *testing.T, url, contentType string, body io.Reader) <-chan result {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			c <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		c <- result{resp, b, err}
	}()
	return c
}

// TestShutdownDrainsInFlightWork stops the server while a publish is blocked
// on a subscriber and an accepted verification is outstanding. run must
// finish both before it returns, and the publisher must get its summary.
func TestShutdownDrainsInFlightWork(t *testing.T) {
	h, l := newHub(t)
	x, y := newSubscriber(t), newSubscriber(t)
	activate(t, h, x.URL+"/x", "x")
	delivering, verifying := make(chan struct{}), make(chan struct{})
	held, release := newRelease(t)
	x.setDeliver(func(r *http.Request) {
		close(delivering)
		hold(r, held)
	})
	y.setVerify(func(w http.ResponseWriter, r *http.Request) {
		close(verifying)
		hold(r, held)
		echoChallenge(w, r)
	})
	base, stop, stopped := start(t, h, time.Minute)

	if res := await(t, post(t, base, formType, strings.NewReader(subscribeForm(y.URL+"/y", "y"))), "subscribe"); res.err != nil || res.resp.StatusCode != http.StatusAccepted {
		t.Fatalf("subscribe: %+v", res)
	}
	await(t, verifying, "the verification")
	published := post(t, base+"/publish", "", nil)
	await(t, delivering, "the delivery")

	stop()
	l.waitFor(t, "msg=draining")
	select {
	case err := <-stopped:
		t.Fatalf("run returned with work in flight: %v", err)
	default:
	}
	release()

	res := await(t, published, "the publish response")
	if res.err != nil {
		t.Fatalf("publish: %v", res.err)
	}
	if sum := decodeSummary(t, res.resp.StatusCode, res.body); sum.Acknowledged != 1 {
		t.Fatalf("publish summary %+v", sum)
	}
	if err := await(t, stopped, "run to return"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, ok := h.subs[y.URL+"/y"]; !ok {
		t.Fatal("verification accepted before shutdown was not completed")
	}
}

// TestShutdownGraceExpiry holds a delivery open past the grace period. run
// must give up at the deadline and report it rather than wait indefinitely.
func TestShutdownGraceExpiry(t *testing.T) {
	h, l := newHub(t)
	x := newSubscriber(t)
	activate(t, h, x.URL+"/x", "x")
	delivering := make(chan struct{})
	held, _ := newRelease(t)
	x.setDeliver(func(r *http.Request) {
		close(delivering)
		hold(r, held)
	})
	base, stop, stopped := start(t, h, 50*time.Millisecond)

	post(t, base+"/publish", "", nil)
	await(t, delivering, "the delivery")
	stop()
	l.waitFor(t, "msg=draining")
	if err := await(t, stopped, "run to return"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run: %v, want the grace deadline", err)
	}
}

// buildHub compiles the program so its signal handling and exit status can be
// observed from outside the process.
func buildHub(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "hub")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func exitCode(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	var err error
	within(t, "the process to exit", func() { err = cmd.Wait() })
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return 0
}

// TestProcessSignal sends SIGTERM to the built program while a publish is in
// flight. It must finish the publish and exit 0; failing to start exits 1.
func TestProcessSignal(t *testing.T) {
	bin := buildHub(t)
	x := newSubscriber(t)
	delivering := make(chan struct{})
	held, release := newRelease(t)
	x.setDeliver(func(r *http.Request) {
		close(delivering)
		hold(r, held)
	})

	l := newLogs()
	cmd := exec.Command(bin, "-addr", "127.0.0.1:0")
	cmd.Stderr = l
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	l.waitFor(t, "msg=listening")
	base := "http://" + regexp.MustCompile(`addr=(\S+)`).FindStringSubmatch(l.String())[1]
	if res := await(t, post(t, base, formType, strings.NewReader(subscribeForm(x.URL+"/x", "x"))), "subscribe"); res.err != nil || res.resp.StatusCode != http.StatusAccepted {
		t.Fatalf("subscribe: %+v", res)
	}
	l.waitFor(t, "msg=verified subscription=1")
	published := post(t, base+"/publish", "", nil)
	await(t, delivering, "the delivery")

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	l.waitFor(t, "msg=draining")
	release()
	res := await(t, published, "the publish response")
	if res.err != nil {
		t.Fatalf("publish: %v", res.err)
	}
	if sum := decodeSummary(t, res.resp.StatusCode, res.body); sum.Acknowledged != 1 {
		t.Fatalf("summary %+v", sum)
	}
	if code := exitCode(t, cmd); code != 0 {
		t.Fatalf("exit status %d after draining, want 0\n%s", code, l)
	}

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	fail := exec.Command(bin, "-addr", taken.Addr().String())
	if err := fail.Start(); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(t, fail); code != 1 {
		t.Fatalf("exit status %d when the address is taken, want 1", code)
	}
}
