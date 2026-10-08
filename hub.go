package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"
)

// lease is fixed: a requested hub.lease_seconds is validated but not honored.
const lease = 24 * time.Hour

// reserveVerification claims verification and storage capacity for sub and
// gives it the next revision. It runs before the 202, so a full or stopping
// hub answers 503 instead.
func (h *Hub) reserveVerification(sub *subscription) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepExpiredLocked()
	_, stored := h.subs[sub.callback]
	known := stored || h.verifying[sub.callback] > 0
	switch {
	case h.closed:
		return errShuttingDown
	case h.verifications >= h.maxVerifying:
		return errors.New("too many verifications in progress")
	case !known && h.callbackCountLocked() >= h.maxCallbacks:
		return errors.New("subscription limit reached")
	}
	h.lastRevision++
	sub.revision = h.lastRevision
	h.verifications++
	h.verifying[sub.callback]++
	h.tasks.Add(1)
	return nil
}

// callbackCountLocked counts distinct callbacks. A stored callback that is
// also being renewed counts once.
func (h *Hub) callbackCountLocked() int {
	n := len(h.subs)
	for callback := range h.verifying {
		if _, stored := h.subs[callback]; !stored {
			n++
		}
	}
	return n
}

// sweepExpiredLocked removes expired records, except those whose callback
// has a verification in progress: the stored revision is what stops that
// older verification from bringing back a superseded secret.
func (h *Hub) sweepExpiredLocked() {
	for callback, sub := range h.subs {
		if !h.isLive(sub) && h.verifying[callback] == 0 {
			delete(h.subs, callback)
		}
	}
}

// verify runs after the 202 has been sent, on a context of its own: the
// registration request is already over.
func (h *Hub) verify(sub subscription) {
	defer h.tasks.Done()
	sub.expiresAt = h.now().Add(lease)
	err := h.confirmIntent(sub.callback)
	h.logVerification(sub, err, h.finishVerification(sub, err == nil))
}

// confirmIntent asks the callback to echo a fresh challenge exactly.
func (h *Hub) confirmIntent(callback string) error {
	challenge := rand.Text()
	// Reading one byte more than the challenge is enough to see a mismatch.
	got, err := h.exchange(context.Background(), http.MethodGet, verifyURL(callback, challenge), nil, "", len(challenge)+1)
	if err != nil {
		return err
	}
	if string(got) != challenge {
		return fmt.Errorf("challenge mismatch: got %d bytes, want %d", len(got), len(challenge))
	}
	return nil
}

// finishVerification releases sub's reservation and stores sub if it verified,
// unless a newer revision is stored; it then returns that revision.
func (h *Hub) finishVerification(sub subscription, verified bool) (supersededBy uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.verifications--
	h.verifying[sub.callback]--
	if h.verifying[sub.callback] == 0 {
		delete(h.verifying, sub.callback)
	}
	if stored, ok := h.subs[sub.callback]; ok && stored.revision > sub.revision {
		return stored.revision
	}
	if verified {
		h.subs[sub.callback] = sub
	}
	return 0
}

// reservePublish claims a publish slot without waiting for one.
func (h *Hub) reservePublish() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.closed:
		return errShuttingDown
	case h.publishing >= h.maxPublishing:
		return errors.New("too many publishes in progress")
	}
	h.publishing++
	return nil
}

// publish delivers one new event to each recipient in turn, until the
// broadcast budget runs out or ctx ends.
func (h *Hub) publish(ctx context.Context) (summary, error) {
	ctx, cancel := context.WithTimeout(ctx, h.broadcastBudget)
	defer cancel()
	ev := event{EventID: rand.Text(), GeneratedAt: h.now().UTC(), Message: eventMessage}
	// Marshaled once: every recipient gets these exact bytes.
	body, err := json.Marshal(ev)
	if err != nil {
		return summary{}, fmt.Errorf("encode event: %w", err)
	}
	sum := summary{EventID: ev.EventID}
	for _, selected := range h.recipients() {
		sum.add(h.deliver(ctx, ev.EventID, selected.callback, body))
	}
	h.log.Info("published", sum.logAttrs()...)
	return sum, nil
}

// recipients returns the live subscriptions in revision order, rotated one
// place per broadcast so the same slow recipients do not always use up the
// budget first.
func (h *Hub) recipients() []subscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepExpiredLocked()
	live := slices.Collect(maps.Values(h.subs))
	live = slices.DeleteFunc(live, func(s subscription) bool { return !h.isLive(s) })
	if len(live) == 0 {
		return nil
	}
	slices.SortFunc(live, func(a, b subscription) int { return cmp.Compare(a.revision, b.revision) })
	start := h.broadcasts % uint64(len(live))
	h.broadcasts++
	return slices.Concat(live[start:], live[:start])
}

func (h *Hub) deliver(ctx context.Context, eventID, callback string, body []byte) outcome {
	if ctx.Err() != nil {
		return notAttempted
	}
	// Re-read so a renewal committed during the broadcast is signed with its
	// new secret. A renewal can still commit just after this read.
	h.mu.Lock()
	sub, ok := h.subs[callback]
	h.mu.Unlock()
	if !ok || !h.isLive(sub) {
		return skippedExpired
	}
	if _, err := h.exchange(ctx, http.MethodPost, callback, body, sign(sub.secret, body), 0); err != nil {
		h.log.Warn("delivery failed", "event", eventID, "subscription", sub.revision, "failure", err)
		return failed
	}
	return acknowledged
}

func (h *Hub) stopAdmission() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
}

// waitVerifications waits for every admitted verification, or until ctx
// ends. It must follow stopAdmission: reserveVerification adds to tasks under
// the same lock that stopAdmission takes, so nothing is added once Wait runs.
func (h *Hub) waitVerifications(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		h.tasks.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("verifications still running: %w", ctx.Err())
	}
}
