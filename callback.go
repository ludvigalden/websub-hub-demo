package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// verifyURL appends the intent-verification query to callback. Appending
// keeps the callback's own query verbatim, repeated names included.
func verifyURL(callback, challenge string) string {
	query := url.Values{
		"hub.mode":          {"subscribe"},
		"hub.topic":         {topic},
		"hub.challenge":     {challenge},
		"hub.lease_seconds": {strconv.Itoa(int(lease.Seconds()))},
	}.Encode()
	if strings.Contains(callback, "?") {
		return callback + "&" + query
	}
	return callback + "?" + query
}

// sign returns the X-Hub-Signature value for body: HMAC-SHA-256 under secret.
func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// exchange makes one callback request within the exchange timeout and
// returns up to limit bytes of a 2xx response. A signed request carries a
// JSON body. Errors name the cause but never the URL, whose query may carry
// credentials.
func (h *Hub) exchange(ctx context.Context, method, target string, body []byte, signature string, limit int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, h.exchangeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid callback")
	}
	if signature != "" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Hub-Signature", signature)
	}
	resp, err := h.client.Do(req)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return nil, errors.New("timeout")
	case errors.Is(err, context.Canceled):
		return nil, errors.New("canceled")
	case err != nil:
		return nil, errors.New("transport failure")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	got, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
	if err != nil {
		return nil, errors.New("response read failed")
	}
	return got, nil
}

// logVerification runs after finishVerification has released the lock.
func (h *Hub) logVerification(sub subscription, err error, supersededBy uint64) {
	switch {
	case err != nil:
		h.log.Warn("verification failed", "subscription", sub.revision, "failure", err)
	case supersededBy != 0:
		h.log.Info("verified but superseded", "subscription", sub.revision, "by", supersededBy)
	default:
		h.log.Info("verified", "subscription", sub.revision)
	}
}
