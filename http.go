package main

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (h *Hub) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /{$}", h.handleSubscribe)
	mux.HandleFunc("POST /publish", h.handlePublish)
	return mux
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func newServer(h *Hub) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Leaves room for a publish to spend its whole budget.
		WriteTimeout: h.broadcastBudget + 2*time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func (h *Hub) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != formType {
		http.Error(w, "expected "+formType, http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "malformed form body", http.StatusBadRequest)
		return
	}
	sub, err := parseSubscription(r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.reserveVerification(&sub); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// The 202 is flushed before the callback is contacted. If the flush fails
	// the hub verifies anyway: the challenge alone decides the outcome.
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusAccepted)
	if err := http.NewResponseController(w).Flush(); err != nil {
		h.log.Warn("acceptance not flushed", "subscription", sub.revision, "err", err)
	}
	go h.verify(sub)
}

func parseSubscription(form url.Values) (subscription, error) {
	for _, key := range []string{"hub.mode", "hub.callback", "hub.topic", "hub.secret", "hub.lease_seconds"} {
		if len(form[key]) > 1 {
			return subscription{}, errors.New("duplicate " + key)
		}
	}
	sub := subscription{callback: form.Get("hub.callback"), secret: form.Get("hub.secret")}
	if form.Get("hub.mode") != "subscribe" {
		return subscription{}, errors.New("hub.mode must be subscribe")
	}
	if !validCallback(sub.callback) {
		return subscription{}, errors.New("hub.callback must be an absolute http(s) URL with a host, without credentials or fragment")
	}
	if form.Get("hub.topic") != topic {
		return subscription{}, errors.New("unknown hub.topic")
	}
	if sub.secret == "" || len(sub.secret) > 199 {
		return subscription{}, errors.New("hub.secret must be 1-199 bytes")
	}
	// The lease is fixed, but a lease that is present must still be valid,
	// and an empty value counts as present.
	if form.Has("hub.lease_seconds") {
		if n, err := strconv.ParseUint(form.Get("hub.lease_seconds"), 10, 32); err != nil || n == 0 {
			return subscription{}, errors.New("hub.lease_seconds must be a positive integer")
		}
	}
	return sub, nil
}

func validCallback(callback string) bool {
	u, err := url.Parse(callback)
	if err != nil {
		return false
	}
	// A literal '#' is refused even when the fragment is empty: the parser
	// drops it, but the appended challenge query would land after it.
	return (u.Scheme == "http" || u.Scheme == "https") &&
		u.Hostname() != "" &&
		u.User == nil &&
		!strings.Contains(callback, "#")
}

// handlePublish delivers within the request: the broadcast ends when the
// budget runs out or the caller goes away, and the summary is the response.
func (h *Hub) handlePublish(w http.ResponseWriter, r *http.Request) {
	if err := h.reservePublish(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer h.releasePublish()
	ctx, cancel := context.WithTimeout(r.Context(), h.broadcastBudget)
	defer cancel()
	sum, err := h.publish(ctx)
	if err != nil {
		http.Error(w, "could not generate event", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sum); err != nil {
		h.log.Warn("publish summary not written", "event", sum.EventID, "err", err)
	}
}
