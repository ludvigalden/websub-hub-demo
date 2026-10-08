// Command websub-hub-demo is a small WebSub hub: it verifies subscriber
// intent and delivers HMAC-SHA-256-signed JSON notifications.
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

// shutdownGrace fits inside Docker's default 10-second stop timeout.
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
		slog.Error("stopped", "err", err)
		os.Exit(1)
	}
}

func newLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

// run serves until ctx ends. It then stops admitting work and gives in-flight
// requests and verifications up to grace to finish.
func run(ctx context.Context, ln net.Listener, h *Hub, grace time.Duration) error {
	srv := newServer(h)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	h.log.Info("listening", "addr", ln.Addr().String())

	select {
	case err := <-served:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	h.log.Info("draining", "grace", grace)
	h.stopAdmission()
	drainCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		return fmt.Errorf("drain requests: %w", err)
	}
	if err := h.waitVerifications(drainCtx); err != nil {
		return err
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	h.log.Info("stopped")
	return nil
}
