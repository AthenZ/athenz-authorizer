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
	"time"
)

// TokenType represents the type of Athenz token
type TokenType int

const (
	// RoleTokenType represents an Athenz role token (v=Z1 format)
	RoleTokenType TokenType = iota
	// AccessTokenType represents an Athenz OAuth2 access token (JWT)
	AccessTokenType
)

// ValidatedToken represents a validated Athenz token with its parsed claims
type ValidatedToken struct {
	// Token type (role token or access token)
	Type TokenType

	// Raw token string
	RawToken string

	// Common fields
	Domain    string
	Principal string
	Roles     []string

	// Timestamps
	IssueTime  time.Time
	ExpiryTime time.Time

	// Role token specific fields
	KeyID     string
	Signature string

	// Access token specific fields (JWT)
	ClientID        string
	Subject         string
	Audience        []string
	Scope           []string
	AuthorizedParty string
}

// IsExpired checks if the token has expired
func (vt *ValidatedToken) IsExpired() bool {
	return time.Now().After(vt.ExpiryTime)
}

// TTL returns the time-to-live duration until expiry
func (vt *ValidatedToken) TTL() time.Duration {
	return time.Until(vt.ExpiryTime)
}

// GetDomain returns the domain of the token
func (vt *ValidatedToken) GetDomain() string {
	return vt.Domain
}

// GetPrincipal returns the principal (user or service) of the token
func (vt *ValidatedToken) GetPrincipal() string {
	return vt.Principal
}

// GetRoles returns the roles associated with the token
func (vt *ValidatedToken) GetRoles() []string {
	return vt.Roles
}
