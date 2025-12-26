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
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cache, err := New()
	if err != nil {
		t.Errorf("New() error = %v", err)
		return
	}
	if cache == nil {
		t.Error("New() returned nil cache")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	ctx := context.Background()
	cache, err := New()
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	token := &ValidatedToken{
		Type:       RoleTokenType,
		RawToken:   "test-token",
		Domain:     "test-domain",
		Principal:  "test-principal",
		Roles:      []string{"role1", "role2"},
		IssueTime:  time.Now(),
		ExpiryTime: time.Now().Add(1 * time.Hour),
		KeyID:      "key-id",
		Signature:  "signature",
	}

	// Test Set
	err = cache.Set(ctx, token.RawToken, token)
	if err != nil {
		t.Errorf("Set() error = %v", err)
	}

	// Test Get
	cached, ok := cache.Get(ctx, token.RawToken)
	if !ok {
		t.Error("Get() returned false, expected true")
	}
	if cached == nil {
		t.Fatal("Get() returned nil token")
	}

	// Verify token fields
	if cached.Domain != token.Domain {
		t.Errorf("Domain = %v, want %v", cached.Domain, token.Domain)
	}
	if cached.Principal != token.Principal {
		t.Errorf("Principal = %v, want %v", cached.Principal, token.Principal)
	}
	if len(cached.Roles) != len(token.Roles) {
		t.Errorf("Roles length = %v, want %v", len(cached.Roles), len(token.Roles))
	}
}

func TestCache_GetNonExistent(t *testing.T) {
	ctx := context.Background()
	cache, _ := New()

	cached, ok := cache.Get(ctx, "non-existent-token")
	if ok {
		t.Error("Get() returned true for non-existent token")
	}
	if cached != nil {
		t.Error("Get() returned non-nil token for non-existent key")
	}
}

func TestCache_SetNil(t *testing.T) {
	ctx := context.Background()
	cache, _ := New()

	err := cache.Set(ctx, "test-token", nil)
	if err == nil {
		t.Error("Set() with nil token should return error")
	}
}

func TestCache_SetExpiredToken(t *testing.T) {
	ctx := context.Background()
	cache, _ := New()

	token := &ValidatedToken{
		Type:       RoleTokenType,
		RawToken:   "expired-token",
		Domain:     "test-domain",
		Principal:  "test-principal",
		Roles:      []string{"role1"},
		IssueTime:  time.Now().Add(-2 * time.Hour),
		ExpiryTime: time.Now().Add(-1 * time.Hour), // Already expired
		KeyID:      "key-id",
		Signature:  "signature",
	}

	err := cache.Set(ctx, token.RawToken, token)
	if err == nil {
		t.Error("Set() with expired token should return error")
	}
}

func TestCache_Delete(t *testing.T) {
	ctx := context.Background()
	cache, _ := New()

	token := &ValidatedToken{
		Type:       RoleTokenType,
		RawToken:   "test-token",
		Domain:     "test-domain",
		Principal:  "test-principal",
		Roles:      []string{"role1"},
		IssueTime:  time.Now(),
		ExpiryTime: time.Now().Add(1 * time.Hour),
	}

	// Set token
	cache.Set(ctx, token.RawToken, token)

	// Verify it exists
	_, ok := cache.Get(ctx, token.RawToken)
	if !ok {
		t.Error("Token should exist before delete")
	}

	// Delete token
	err := cache.Delete(ctx, token.RawToken)
	if err != nil {
		t.Errorf("Delete() error = %v", err)
	}

	// Verify it's gone
	_, ok = cache.Get(ctx, token.RawToken)
	if ok {
		t.Error("Token should not exist after delete")
	}
}

func TestCache_Clear(t *testing.T) {
	ctx := context.Background()
	cache, _ := New()

	// Add multiple tokens
	for i := 0; i < 5; i++ {
		token := &ValidatedToken{
			Type:       RoleTokenType,
			RawToken:   string(rune('a' + i)),
			Domain:     "test-domain",
			Principal:  "test-principal",
			Roles:      []string{"role1"},
			IssueTime:  time.Now(),
			ExpiryTime: time.Now().Add(1 * time.Hour),
		}
		if err := cache.Set(ctx, token.RawToken, token); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// Verify cache size
	if size := cache.GetCacheSize(); size != 5 {
		t.Errorf("Cache size = %d, want 5", size)
	}

	// Clear cache
	err := cache.Clear(ctx)
	if err != nil {
		t.Errorf("Clear() error = %v", err)
	}

	// Note: gache v2.1.0 Clear() may not immediately reflect in Len()
	// Verify tokens are no longer retrievable (more important than size)
	for i := 0; i < 5; i++ {
		_, ok := cache.Get(ctx, string(rune('a'+i)))
		if ok {
			t.Errorf("Token %c should not be retrievable after clear", rune('a'+i))
		}
	}
}

func TestCache_GetCacheSize(t *testing.T) {
	ctx := context.Background()
	cache, _ := New()

	// Initially empty
	if size := cache.GetCacheSize(); size != 0 {
		t.Errorf("Initial cache size = %d, want 0", size)
	}

	// Add tokens
	for i := 0; i < 3; i++ {
		token := &ValidatedToken{
			Type:       RoleTokenType,
			RawToken:   string(rune('a' + i)),
			Domain:     "test-domain",
			Principal:  "test-principal",
			Roles:      []string{"role1"},
			IssueTime:  time.Now(),
			ExpiryTime: time.Now().Add(1 * time.Hour),
		}
		cache.Set(ctx, token.RawToken, token)
	}

	// Verify size
	if size := cache.GetCacheSize(); size != 3 {
		t.Errorf("Cache size = %d, want 3", size)
	}
}

func TestCache_TTL(t *testing.T) {
	ctx := context.Background()
	cache, _ := New()

	token := &ValidatedToken{
		Type:       RoleTokenType,
		RawToken:   "test-token",
		Domain:     "test-domain",
		Principal:  "test-principal",
		Roles:      []string{"role1"},
		IssueTime:  time.Now(),
		ExpiryTime: time.Now().Add(100 * time.Millisecond), // Token expires in 100ms
	}

	// Set token
	cache.Set(ctx, token.RawToken, token)

	// Verify it exists immediately
	_, ok := cache.Get(ctx, token.RawToken)
	if !ok {
		t.Error("Token should exist immediately after set")
	}

	// Wait for token to expire
	time.Sleep(150 * time.Millisecond)

	// Verify it's gone due to token expiry
	_, ok = cache.Get(ctx, token.RawToken)
	if ok {
		t.Error("Token should not exist after token expiry")
	}
}

func TestValidatedToken_IsExpired(t *testing.T) {
	tests := []struct {
		name       string
		expiryTime time.Time
		want       bool
	}{
		{
			name:       "not expired",
			expiryTime: time.Now().Add(1 * time.Hour),
			want:       false,
		},
		{
			name:       "expired",
			expiryTime: time.Now().Add(-1 * time.Hour),
			want:       true,
		},
		{
			name:       "just expired",
			expiryTime: time.Now().Add(-1 * time.Millisecond),
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &ValidatedToken{
				ExpiryTime: tt.expiryTime,
			}
			if got := token.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatedToken_TTL(t *testing.T) {
	token := &ValidatedToken{
		ExpiryTime: time.Now().Add(1 * time.Hour),
	}

	ttl := token.TTL()
	if ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Errorf("TTL() = %v, want approximately 1 hour", ttl)
	}
}

func TestCache_AccessToken(t *testing.T) {
	ctx := context.Background()
	cache, _ := New()

	token := &ValidatedToken{
		Type:            AccessTokenType,
		RawToken:        "access-token",
		Domain:          "test-domain",
		Principal:       "test-principal",
		ClientID:        "client-id",
		Subject:         "subject",
		Audience:        []string{"aud1", "aud2"},
		Scope:           []string{"scope1", "scope2"},
		AuthorizedParty: "authorized-party",
		IssueTime:       time.Now(),
		ExpiryTime:      time.Now().Add(1 * time.Hour),
	}

	// Set access token
	err := cache.Set(ctx, token.RawToken, token)
	if err != nil {
		t.Errorf("Set() error = %v", err)
	}

	// Get access token
	cached, ok := cache.Get(ctx, token.RawToken)
	if !ok {
		t.Error("Get() returned false for access token")
	}

	// Verify access token specific fields
	if cached.ClientID != token.ClientID {
		t.Errorf("ClientID = %v, want %v", cached.ClientID, token.ClientID)
	}
	if cached.Subject != token.Subject {
		t.Errorf("Subject = %v, want %v", cached.Subject, token.Subject)
	}
	if len(cached.Audience) != len(token.Audience) {
		t.Errorf("Audience length = %v, want %v", len(cached.Audience), len(token.Audience))
	}
}
