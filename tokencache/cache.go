// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tokencache

import (
	"context"
	"time"

	"github.com/kpango/gache/v2"
	"github.com/pkg/errors"
)

// Cache represents a high-performance token validation cache
type Cache interface {
	// Get retrieves a validated token from cache
	Get(ctx context.Context, token string) (*ValidatedToken, bool)

	// Set stores a validated token in cache with TTL
	Set(ctx context.Context, token string, validated *ValidatedToken) error

	// Delete removes a token from cache
	Delete(ctx context.Context, token string) error

	// Clear removes all tokens from cache
	Clear(ctx context.Context) error

	// GetCacheSize returns the number of entries in cache
	GetCacheSize() int

	// StartExpiredHook starts the background goroutine to handle expired entries
	StartExpiredHook(ctx context.Context, purgePeriod time.Duration)
}

type cache struct {
	gache gache.Gache[*ValidatedToken]
}

// New creates a new token cache instance
func New(opts ...Option) (Cache, error) {
	g := gache.New[*ValidatedToken]()
	c := &cache{
		gache: g,
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, errors.Wrap(err, "error creating token cache")
		}
	}

	return c, nil
}

// generateKey creates a cache key from token
func generateKey(token string) string {
	return token
}

// Get retrieves a validated token from cache
func (c *cache) Get(ctx context.Context, token string) (*ValidatedToken, bool) {
	key := generateKey(token)
	validated, ok := c.gache.Get(key)
	if !ok {
		return nil, false
	}

	// Double check expiration (defense in depth)
	if validated.IsExpired() {
		c.gache.Delete(key)
		return nil, false
	}

	return validated, true
}

// Set stores a validated token in cache with TTL based on token's expiry time
func (c *cache) Set(ctx context.Context, token string, validated *ValidatedToken) error {
	if validated == nil {
		return errors.New("validated token is nil")
	}

	key := generateKey(token)
	ttl := validated.TTL()

	// Ensure TTL is positive
	if ttl <= 0 {
		return errors.New("token TTL is not positive")
	}

	c.gache.SetWithExpire(key, validated, ttl)

	return nil
}

// Delete removes a token from cache
func (c *cache) Delete(ctx context.Context, token string) error {
	key := generateKey(token)
	c.gache.Delete(key)
	return nil
}

// Clear removes all tokens from cache
func (c *cache) Clear(ctx context.Context) error {
	c.gache.Clear()
	return nil
}

// GetCacheSize returns the number of entries in cache
func (c *cache) GetCacheSize() int {
	return c.gache.Len()
}

// StartExpiredHook starts the background goroutine to handle expired entries
func (c *cache) StartExpiredHook(ctx context.Context, purgePeriod time.Duration) {
	c.gache.StartExpired(ctx, purgePeriod)
}
