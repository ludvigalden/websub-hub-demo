// Command websub-hub-demo is a compact WebSub hub demonstration: it verifies
// subscriber intent and distributes HMAC-SHA-256-signed JSON notifications.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// shutdownGrace fits inside Docker's default 10-second stop timeout and
// exceeds the broadcast budget, so a publish in flight at SIGTERM completes.
const shutdownGrace = 9 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ln, err := net.Listen("tcp", ":8080")
	if err == nil {
		err = run(ctx, ln, NewHub(), shutdownGrace)
	}
	stop()
	if err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func newServer(h *Hub) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		// Bounds a stalled request body; the form limit keeps legitimate
		// bodies far below what this allows.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: h.budget + 2*time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// run serves until ctx is done, then stops admission and drains all admitted
// work within grace. Past grace it cancels outstanding exchanges and closes
// connections, but still returns only once every task has.
func run(ctx context.Context, ln net.Listener, h *Hub, grace time.Duration) error {
	srv := newServer(h)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	h.log.Info("listening", "addr", ln.Addr().String())

	var errs []error
	select {
	case err := <-served:
		errs = append(errs, fmt.Errorf("serve: %w", err))
		served <- nil
	case <-ctx.Done():
	}

	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.log.Info("draining", "grace", grace)
	drainCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	keepRunning := context.AfterFunc(drainCtx, h.abort)
	if err := srv.Shutdown(drainCtx); err != nil {
		errs = append(errs, fmt.Errorf("drain requests: %w", errors.Join(err, srv.Close())))
	}
	h.tasks.Wait()
	if !keepRunning() {
		errs = append(errs, errors.New("grace period expired: outstanding work was canceled"))
	}
	if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs = append(errs, fmt.Errorf("serve: %w", err))
	}
	if len(errs) == 0 {
		h.log.Info("stopped")
	}
	return errors.Join(errs...)
}
