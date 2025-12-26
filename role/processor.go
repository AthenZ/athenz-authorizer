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

package role

import (
	"context"
	"strings"

	"github.com/AthenZ/athenz-authorizer/v5/pubkey"
	"github.com/AthenZ/athenz-authorizer/v5/tokencache"
	"github.com/pkg/errors"
)

// Processor represents the role token parser interface.
type Processor interface {
	ParseAndValidateRoleToken(tok string) (*Token, error)
}

type rtp struct {
	pkp   pubkey.Provider
	cache tokencache.Cache
}

// New returns the Role instance.
func New(opts ...Option) (Processor, error) {
	r := new(rtp)
	for _, opt := range append(defaultOptions, opts...) {
		if err := opt(r); err != nil {
			return nil, errors.Wrap(err, "error create role token processor")
		}
	}
	return r, nil
}

// ParseAndValidateRoleToken return the parsed and validated role token, and return any parsing and validate errors.
func (r *rtp) ParseAndValidateRoleToken(tok string) (*Token, error) {
	// Check cache first if enabled
	if r.cache != nil {
		if cached, found := r.cache.Get(context.Background(), tok); found {
			return validatedTokenToRoleToken(cached), nil
		}
	}

	rt, err := r.parseToken(tok)
	if err != nil {
		return nil, errors.Wrap(err, "error parse role token")
	}

	if err = r.validate(rt); err != nil {
		return nil, errors.Wrap(err, "error validate role token")
	}

	// Store in cache if enabled
	if r.cache != nil {
		validated := roleTokenToValidatedToken(rt, tok)
		_ = r.cache.Set(context.Background(), tok, validated)
	}

	return rt, nil
}

func (r *rtp) parseToken(tok string) (*Token, error) {
	st := strings.SplitN(tok, ";s=", 2)
	if len(st) != 2 {
		return nil, errors.Wrap(ErrRoleTokenInvalid, "no signature found")
	}

	rt := &Token{
		UnsignedToken: st[0],
		Signature:     st[1],
	}

	for _, pair := range strings.Split(st[0], ";") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, errors.Wrap(ErrRoleTokenInvalid, "invalid key value format")
		}
		if err := rt.SetParams(kv[0], kv[1]); err != nil {
			return nil, errors.Wrap(err, "error setting value")
		}
	}

	return rt, nil
}

func (r *rtp) validate(rt *Token) error {
	if rt.Expired() {
		return errors.Wrapf(ErrRoleTokenExpired, "token expired. principal %s", rt.Principal)
	}
	ver := r.pkp(pubkey.EnvZTS, rt.KeyID)
	if ver == nil {
		return errors.Wrapf(ErrRoleTokenInvalid, "invalid role token key ID %s. principal %s", rt.KeyID, rt.Principal)
	}
	return ver.Verify(rt.UnsignedToken, rt.Signature)
}

// roleTokenToValidatedToken converts role.Token to tokencache.ValidatedToken
func roleTokenToValidatedToken(rt *Token, rawToken string) *tokencache.ValidatedToken {
	return &tokencache.ValidatedToken{
		Type:       tokencache.RoleTokenType,
		RawToken:   rawToken,
		Domain:     rt.Domain,
		Principal:  rt.Principal,
		Roles:      rt.Roles,
		IssueTime:  rt.TimeStamp,
		ExpiryTime: rt.ExpiryTime,
		KeyID:      rt.KeyID,
		Signature:  rt.Signature,
	}
}

// validatedTokenToRoleToken converts tokencache.ValidatedToken to role.Token
func validatedTokenToRoleToken(vt *tokencache.ValidatedToken) *Token {
	return &Token{
		Domain:        vt.Domain,
		Roles:         vt.Roles,
		Principal:     vt.Principal,
		TimeStamp:     vt.IssueTime,
		ExpiryTime:    vt.ExpiryTime,
		KeyID:         vt.KeyID,
		Signature:     vt.Signature,
		UnsignedToken: extractUnsignedToken(vt.RawToken),
	}
}

// extractUnsignedToken extracts the unsigned part from a role token
func extractUnsignedToken(rawToken string) string {
	parts := strings.SplitN(rawToken, ";s=", 2)
	if len(parts) == 2 {
		return parts[0]
	}
	return rawToken
}
