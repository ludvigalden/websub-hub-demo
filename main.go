// Command websub-hub-demo is a compact WebSub hub demonstration: it verifies
// subscriber intent and distributes HMAC-SHA-256-signed JSON notifications.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// shutdownGrace bounds graceful draining, not termination: past it the hub
// cancels and then joins what remains. It sits inside Docker's default
// 10-second stop timeout and above the broadcast budget.
const shutdownGrace = 9 * time.Second

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()
	slog.SetDefault(newLogger(os.Stderr))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ln, err := net.Listen("tcp", *addr)
	if err == nil {
		err = run(ctx, ln, NewHub(), shutdownGrace)
	}
	stop()
	if err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func newLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func newServer(h *Hub) *http.Server {
	return &http.Server{
		Handler: h,
		// A forced stop cancels request contexts directly, without relying on
		// the server noticing closed connections.
		BaseContext:       func(net.Listener) context.Context { return h.ctx },
		ReadHeaderTimeout: 5 * time.Second,
		// Bounds a stalled request body; the form limit keeps legitimate
		// bodies far below what this allows.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: h.budget + 2*time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// run serves until ctx is done, then stops admission and drains admitted
// work for up to grace. Past grace it cancels outstanding work and closes
// connections, and it returns only once every admitted task has.
func run(ctx context.Context, ln net.Listener, h *Hub, grace time.Duration) error {
	srv := newServer(h)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	h.log.Info("listening", "addr", ln.Addr().String())

	var errs []error
	serveReturned := false
	select {
	case err := <-served:
		errs, serveReturned = append(errs, fmt.Errorf("serve: %w", err)), true
	case <-ctx.Done():
	}

	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.log.Info("draining", "grace", grace)
	drainCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	cancelAbort := context.AfterFunc(drainCtx, h.abort)
	if err := srv.Shutdown(drainCtx); err != nil {
		errs = append(errs, fmt.Errorf("drain requests: %w", errors.Join(err, srv.Close())))
	}
	h.tasks.Wait()
	if !cancelAbort() {
		errs = append(errs, errors.New("grace period expired: outstanding work was canceled"))
	}
	if !serveReturned {
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, fmt.Errorf("serve: %w", err))
		}
	}
	if len(errs) == 0 {
		h.log.Info("stopped")
	}
	return errors.Join(errs...)
}
