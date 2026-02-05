/*
 * © 2023 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package snyk

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rate limit defaults: stay under Snyk's 160 req/sec limit
const (
	defaultRateLimit = 150 // requests per second
	defaultBurst     = 10  // burst allowance
)

var snykRateLimiter = newRateLimiter()

// rateLimiter provides both proactive throttling and reactive backoff.
// All goroutines share this limiter so they coordinate together.
type rateLimiter struct {
	mu           sync.Mutex
	backoffUntil time.Time

	// Proactive token bucket: limits requests/second before hitting API
	tokenBucket *rate.Limiter
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		tokenBucket: rate.NewLimiter(defaultRateLimit, defaultBurst),
	}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	// First: proactive throttling via token bucket
	if err := r.tokenBucket.Wait(ctx); err != nil {
		return err
	}

	// Second: reactive backoff if we got a 429
	for {
		r.mu.Lock()
		if r.backoffUntil.IsZero() || !time.Now().Before(r.backoffUntil) {
			r.mu.Unlock()
			return nil
		}
		wait := time.Until(r.backoffUntil)
		r.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			// Re-check in case backoffUntil was extended
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func (r *rateLimiter) backoff(d time.Duration) {
	if d <= 0 {
		return
	}
	until := time.Now().Add(d)
	r.mu.Lock()
	if until.After(r.backoffUntil) {
		r.backoffUntil = until
	}
	r.mu.Unlock()
}

type rateLimitTransport struct {
	base    http.RoundTripper
	limiter *rateLimiter
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.limiter != nil {
		if err := t.limiter.wait(req.Context()); err != nil {
			return nil, err
		}
	}
	return t.base.RoundTrip(req)
}

// parseRateLimitResetHeader parses the X-RateLimit-Reset header value.
// Snyk returns this as seconds until reset (e.g., "1" means 1 second).
func parseRateLimitResetHeader(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}

	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil || sec <= 0 {
		return 0, false
	}

	return time.Duration(sec) * time.Second, true
}
