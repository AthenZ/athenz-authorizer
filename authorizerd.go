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

package authorizerd

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/golang-jwt/jwt/v4/request"
	"github.com/kpango/gache/v2"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/AthenZ/athenz-authorizer/v5/access"
	"github.com/AthenZ/athenz-authorizer/v5/jwk"
	"github.com/AthenZ/athenz-authorizer/v5/policy"
	"github.com/AthenZ/athenz-authorizer/v5/pubkey"
	"github.com/AthenZ/athenz-authorizer/v5/role"
)

// Authorizerd represents a daemon for user to verify the role token
type Authorizerd interface {
	// Init initializes the child daemons synchronously
	Init(ctx context.Context) error
	// Start starts the background updater of the child daemons asynchronously
	Start(ctx context.Context) <-chan error

	Verify(r *http.Request, act, res string) error
	Authorize(r *http.Request, act, res string) (Principal, error)
	VerifyAccessToken(ctx context.Context, tok, act, res string, cert *x509.Certificate) error
	AuthorizeAccessToken(ctx context.Context, tok, act, res string, cert *x509.Certificate) (Principal, error)
	VerifyRoleToken(ctx context.Context, tok, act, res string) error
	AuthorizeRoleToken(ctx context.Context, tok, act, res string) (Principal, error)
	VerifyRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) error
	AuthorizeRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) (Principal, error)
	GetPolicyCache(ctx context.Context) map[string][]*policy.Assertion
	GetPrincipalCacheLen() int
	GetPrincipalCacheSize() int64
}

type authorizer func(r *http.Request, act, res string) (Principal, error)

type authority struct {
	//
	pubkeyd         pubkey.Daemon
	policyd         policy.Daemon
	jwkd            jwk.Daemon
	roleProcessor   role.Processor
	accessProcessor access.Processor
	authorizers     []authorizer

	// athenz connection parameters
	athenzURL string
	client    *http.Client

	// successful result cache
	cache            gache.Gache[Principal]
	cacheExp         time.Duration
	cacheMemoryUsage *atomic.Int64

	// roleCertURIPrefix
	roleCertURIPrefix string

	// pubkeyd parameters
	disablePubkeyd        bool
	pubkeyRefreshPeriod   string
	pubkeyRetryDelay      string
	pubkeySysAuthDomain   string
	pubkeyETagExpiry      string
	pubkeyETagPurgePeriod string

	// policyd parameters
	disablePolicyd      bool
	athenzDomains       []string
	policyExpiryMargin  string
	policyRefreshPeriod string
	policyPurgePeriod   string
	policyRetryDelay    string
	policyRetryAttempts int

	// jwkd parameters
	disableJwkd      bool
	jwkRefreshPeriod string
	jwkRetryDelay    string
	jwkURLs          []string

	// accessTokenProcessor parameters
	accessTokenParam AccessTokenParam

	// roleTokenProcessor parameters
	enableRoleToken bool
	roleAuthHeader  string

	// roleCertificateProcessor parameters
	enableRoleCert bool

	// Athenz action/resource mapping parameters
	translator     Translator
	resourcePrefix string

	// log parameters
	outputAuthorizedPrincipalLog bool
}

type mode uint8

const (
	cacheKeyDelimiter      = ':'
	roleInCNDelimiter      = ":role."
	roleToken         mode = iota
	accessToken
)

// New creates the Authorizerd object with the options
func New(opts ...Option) (Authorizerd, error) {
	var (
		prov = &authority{
			cache:            gache.New[Principal](),
			cacheMemoryUsage: &atomic.Int64{},
		}
		err    error
		pkPro  pubkey.Provider
		jwkPro jwk.Provider
	)

	for _, opt := range append(defaultOptions, opts...) {
		if err = opt(prov); err != nil {
			return nil, errors.Wrap(err, "error creating authorizerd")
		}
	}

	// enable ExpiredHook
	prov.cache.EnableExpiredHook().
		SetExpiredHook(prov.cacheExpiredHook)

	if !prov.disablePubkeyd {
		if prov.pubkeyd, err = pubkey.New(
			pubkey.WithAthenzURL(prov.athenzURL),
			pubkey.WithSysAuthDomain(prov.pubkeySysAuthDomain),
			pubkey.WithETagExpiry(prov.pubkeyETagExpiry),
			pubkey.WithETagPurgePeriod(prov.pubkeyETagPurgePeriod),
			pubkey.WithRefreshPeriod(prov.pubkeyRefreshPeriod),
			pubkey.WithRetryDelay(prov.pubkeyRetryDelay),
			pubkey.WithHTTPClient(prov.client),
		); err != nil {
			return nil, err
		}
		pkPro = prov.pubkeyd.GetProvider()
	}

	if !prov.disablePolicyd {
		if prov.policyd, err = policy.New(
			policy.WithAthenzURL(prov.athenzURL),
			policy.WithAthenzDomains(prov.athenzDomains...),
			policy.WithExpiryMargin(prov.policyExpiryMargin),
			policy.WithRefreshPeriod(prov.policyRefreshPeriod),
			policy.WithPurgePeriod(prov.policyPurgePeriod),
			policy.WithRetryDelay(prov.policyRetryDelay),
			policy.WithRetryAttempts(prov.policyRetryAttempts),
			policy.WithHTTPClient(prov.client),
			policy.WithPubKeyProvider(pkPro),
		); err != nil {
			return nil, err
		}
	}

	if !prov.disableJwkd {
		if prov.jwkd, err = jwk.New(
			jwk.WithAthenzJwksURL(prov.athenzURL),
			jwk.WithRefreshPeriod(prov.jwkRefreshPeriod),
			jwk.WithRetryDelay(prov.jwkRetryDelay),
			jwk.WithURLs(prov.jwkURLs),
			jwk.WithHTTPClient(prov.client),
		); err != nil {
			return nil, err
		}
		jwkPro = prov.jwkd.GetProvider()
	}

	if prov.enableRoleToken {
		if prov.roleProcessor, err = role.New(
			role.WithPubkeyProvider(pkPro),
		); err != nil {
			return nil, err
		}
	}

	if prov.accessTokenParam.enable {
		if prov.accessProcessor, err = access.New(
			access.WithJWKProvider(jwkPro),
			access.WithEnableMTLSCertificateBoundAccessToken(prov.accessTokenParam.verifyCertThumbprint),
			access.WithEnableVerifyClientID(prov.accessTokenParam.verifyClientID),
			access.WithAuthorizedClientIDs(prov.accessTokenParam.authorizedClientIDs),
			access.WithClientCertificateGoBackSeconds(prov.accessTokenParam.certBackdateDur),
			access.WithClientCertificateOffsetSeconds(prov.accessTokenParam.certOffsetDur),
		); err != nil {
			return nil, err
		}
	}

	// create authorizers
	if err = prov.initAuthorizers(); err != nil {
		return nil, errors.Wrap(err, "error create authorizers")
	}

	return prov, nil
}

func (a *authority) initAuthorizers() error {
	// TODO: check empty credentials to speed up the checking
	authorizers := make([]authorizer, 0, 3) // rolecert, access token, roletoken

	if a.enableRoleCert {
		rcVerifier := func(r *http.Request, act, res string) (Principal, error) {
			if r.TLS != nil {
				return a.AuthorizeRoleCert(r.Context(), r.TLS.PeerCertificates, act, res)
			}
			return a.AuthorizeRoleCert(r.Context(), nil, act, res)
		}
		glg.Info("initAuthorizers: added role certificate authorizer")
		authorizers = append(authorizers, rcVerifier)
	}

	if a.accessTokenParam.enable {
		atVerifier := func(r *http.Request, act, res string) (Principal, error) {
			tokenString, err := request.AuthorizationHeaderExtractor.ExtractToken(r)
			if err != nil {
				return nil, err
			}
			if r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
				return a.authorize(r.Context(), accessToken, tokenString, act, res, r.URL.RawQuery, r.TLS.PeerCertificates[0])
			}
			return a.authorize(r.Context(), accessToken, tokenString, act, res, r.URL.RawQuery, nil)
		}
		glg.Infof("initAuthorizers: added access token authorizer having param: %+v", a.accessTokenParam)
		authorizers = append(authorizers, atVerifier)
	}

	if a.enableRoleToken {
		rtVerifier := func(r *http.Request, act, res string) (Principal, error) {
			return a.authorize(r.Context(), roleToken, r.Header.Get(a.roleAuthHeader), act, res, r.URL.RawQuery, nil)
		}
		glg.Info("initAuthorizers: added role token authorizer")
		authorizers = append(authorizers, rtVerifier)
	}

	if len(authorizers) < 1 {
		return errors.New("error no authorizers")
	}

	// resize
	a.authorizers = make([]authorizer, len(authorizers))
	copy(a.authorizers[0:], authorizers)
	return nil
}

// Init initializes child daemons synchronously.
func (a *authority) Init(ctx context.Context) error {
	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		select {
		case <-egCtx.Done():
			return egCtx.Err()
		default:
			if !a.disablePubkeyd {
				err := a.pubkeyd.Update(egCtx)
				if err != nil {
					return err
				}
			}
			if !a.disablePolicyd {
				return a.policyd.Update(egCtx)
			}
			return nil
		}
	})
	if !a.disableJwkd {
		eg.Go(func() error {
			select {
			case <-egCtx.Done():
				return egCtx.Err()
			default:
				return a.jwkd.Update(egCtx)
			}
		})
	}

	return eg.Wait()
}

// Start starts authority daemon.
func (a *authority) Start(ctx context.Context) <-chan error {
	var (
		ech              = make(chan error, 200)
		g                = a.cache.StartExpired(ctx, a.cacheExp/2)
		cech, pech, jech <-chan error
	)

	if !a.disablePubkeyd {
		cech = a.pubkeyd.Start(ctx)
	}
	if !a.disablePolicyd {
		pech = a.policyd.Start(ctx)
	}
	if !a.disableJwkd {
		jech = a.jwkd.Start(ctx)
	}

	go func() {
		defer close(ech)
		for {
			select {
			case <-ctx.Done():
				g.Stop()
				g.Clear()
				ech <- ctx.Err()
				return
			case err := <-cech:
				if err != nil {
					ech <- errors.Wrap(err, "update pubkey error")
				}
			case err := <-pech:
				if err != nil {
					ech <- errors.Wrap(err, "update policy error")
				}
			case err := <-jech:
				if err != nil {
					ech <- errors.Wrap(err, "update jwk error")
				}
			}
		}
	}()

	return ech
}

// VerifyRoleToken verifies the role token for specific resource and return and verification error.
func (a *authority) VerifyRoleToken(ctx context.Context, tok, act, res string) error {
	_, err := a.authorize(ctx, roleToken, tok, act, res, "", nil)
	return err
}

// AuthorizeRoleToken verifies the role token for specific resource and returns the result of verifying or verification error if unauthorized.
func (a *authority) AuthorizeRoleToken(ctx context.Context, tok, act, res string) (Principal, error) {
	return a.authorize(ctx, roleToken, tok, act, res, "", nil)
}

// VerifyAccessToken verifies the access token on the specific (action, resource) pair and returns verification error if unauthorized.
func (a *authority) VerifyAccessToken(ctx context.Context, tok, act, res string, cert *x509.Certificate) error {
	_, err := a.authorize(ctx, accessToken, tok, act, res, "", cert)
	return err
}

// AuthorizeAccessToken verifies the access token on the specific (action, resource) pair and returns the result of verifying or verification error if unauthorized.
func (a *authority) AuthorizeAccessToken(ctx context.Context, tok, act, res string, cert *x509.Certificate) (Principal, error) {
	return a.authorize(ctx, accessToken, tok, act, res, "", cert)
}

func (a *authority) authorize(ctx context.Context, m mode, tok, act, res, query string, cert *x509.Certificate) (Principal, error) {
	var key strings.Builder
	key.WriteString(tok)

	if cert != nil {
		key.WriteRune(cacheKeyDelimiter)
		key.WriteString(cert.Issuer.CommonName)
		key.WriteRune(cacheKeyDelimiter)
		key.WriteString(cert.Subject.CommonName)
	}

	if !a.disablePolicyd {
		if act == "" || res == "" {
			return nil, errors.Wrap(ErrInvalidParameters, "empty action / resource")
		}
		key.WriteRune(cacheKeyDelimiter)
		key.WriteString(act)
		key.WriteRune(cacheKeyDelimiter)
		key.WriteString(res)
		if query != "" && a.translator != nil {
			key.WriteRune(cacheKeyDelimiter)
			key.WriteString(query)
		}
	}

	// check if exists in verification success cache
	cached, ok := a.cache.Get(key.String())
	if ok {
		glg.DebugFunc(func() string {
			return fmt.Sprintf("use cached result. masked tok: %s, masked key: %s", maskToken(m, tok), maskCacheKey(key.String(), tok))
		})

		if a.outputAuthorizedPrincipalLog {
			glg.Infof("access authorized by cache, principal: %s, action: %s, resource: %s", cached.(Principal).Name(), act, res)
		}
		return cached.(Principal), nil
	}

	var (
		domain string
		roles  []string
		p      Principal
	)

	switch m {
	case roleToken:
		rt, err := a.roleProcessor.ParseAndValidateRoleToken(tok)
		if err != nil {
			glg.Infof("error parse and validate role token, err: %v", err)
			return nil, errors.Wrap(err, "error authorize role token")
		}
		domain = rt.Domain
		roles = rt.Roles
		p = &principal{
			name:       rt.Principal,
			roles:      rt.Roles,
			domain:     rt.Domain,
			issueTime:  rt.TimeStamp.Unix(),
			expiryTime: rt.ExpiryTime.Unix(),
		}
	case accessToken:
		ac, err := a.accessProcessor.ParseAndValidateOAuth2AccessToken(tok, cert)
		if err != nil {
			glg.Infof("error parse and validate access token, err: %v", err)
			return nil, errors.Wrap(err, "error authorize access token")
		}
		domain = ac.Audience
		roles = ac.Scope
		p = &oAuthAccessToken{
			principal: principal{
				name:       ac.Subject,
				roles:      ac.Scope,
				domain:     ac.Audience,
				issueTime:  ac.IssuedAt,
				expiryTime: ac.ExpiresAt,
			},
			clientID: ac.ClientID,
		}
	}

	if !a.disablePolicyd {
		if a.translator != nil {
			var err error
			act, res, err = a.translator.Translate(domain, act, res, query)
			if err != nil {
				glg.Infof("translator error, err: %v, principal: %s, action: %s, resource: %s", err, p.Name(), act, res)
				return nil, err
			}
		}

		res = a.resourcePrefix + res
		authorizedRoles, err := a.policyd.CheckPolicyRoles(ctx, domain, roles, act, res)
		if err != nil {
			glg.Infof("check policy error, err: %v, principal: %s, action: %s, resource: %s", err, p.Name(), act, res)
			return nil, errors.Wrap(err, "token unauthorized")
		}

		switch typedP := p.(type) {
		case *principal:
			typedP.authorizedRoles = authorizedRoles
		case *oAuthAccessToken:
			typedP.authorizedRoles = authorizedRoles
		}
	}

	glg.DebugFunc(func() string {
		return fmt.Sprintf("set token result. masked tok: %s, masked key: %s, act: %s, res: %s", maskToken(m, tok), maskCacheKey(key.String(), tok), act, res)
	})
	a.cache.SetWithExpire(key.String(), p, a.cacheExp)

	// Calculate memory usage of key and principal that cannot be calculated with gache.Size()
	principalCacheSize := principalCacheMemoryUsage(key.String(), p)

	a.cacheMemoryUsage.Add(principalCacheSize)

	if a.outputAuthorizedPrincipalLog {
		glg.Infof("access authorized, principal: %s, action: %s, resource: %s", p.Name(), act, res)
	}

	return p, nil
}

// principalCacheMemoryUsage returns memory usage of principal
func principalCacheMemoryUsage(key string, p Principal) int64 {
	structSize := int64(unsafe.Sizeof(p))
	name := p.Name()
	domain := p.Domain()

	nameSize := int64(len(name)) + int64(unsafe.Sizeof(name))
	domainSize := int64(len(domain)) + int64(unsafe.Sizeof(domain))

	rolesSize := int64(unsafe.Sizeof(p.Roles()))
	for _, role := range p.Roles() {
		rolesSize += int64(len(role)) + int64(unsafe.Sizeof(role))
	}

	authorizedRolesSize := int64(unsafe.Sizeof(p.AuthorizedRoles()))
	for _, role := range p.AuthorizedRoles() {
		authorizedRolesSize += int64(len(role)) + int64(unsafe.Sizeof(role))
	}

	// memory usage of issueTime and expiryTime
	const int64Size = 8
	timesSize := int64Size * 2

	return structSize + nameSize + domainSize + rolesSize + authorizedRolesSize + int64(timesSize) + int64(len(key))
}

// GetPrincipalCacheLen returns entries number of cached principals
func (a *authority) GetPrincipalCacheLen() int {
	return a.cache.Len()
}

// GetPrincipalCacheSize returns memory usage of cached principals
func (a *authority) GetPrincipalCacheSize() int64 {
	return int64(a.cache.Size()) + a.cacheMemoryUsage.Load()
}

// cacheExpiredHook refreshes the value of cacheMemoryUsage when the cache expires.
func (prov *authority) cacheExpiredHook(ctx context.Context, key string, value Principal) {
	cacheUsage := principalCacheMemoryUsage(key, value)
	prov.cacheMemoryUsage.Add(-cacheUsage)
}

// Verify returns error of verification. Returns nil if ANY authorizer succeeds (OR logic).
func (a *authority) Verify(r *http.Request, act, res string) error {
	for _, verifier := range a.authorizers {
		// OR logic on multiple credentials
		_, err := verifier(r, act, res)
		if err == nil {
			return nil
		}
	}

	return ErrInvalidCredentials
}

// Authorize returns the principal or an error if unauthorized. Returns the principal with nil error if ANY authorizer succeeds (OR logic).
func (a *authority) Authorize(r *http.Request, act, res string) (Principal, error) {
	for _, verifier := range a.authorizers {
		// OR logic on multiple credentials
		verified, err := verifier(r, act, res)
		if err == nil {
			return verified, nil
		}
	}

	return nil, ErrInvalidCredentials
}

// VerifyRoleCert verifies the role certificate for specific resource and return and verification error.
func (a *authority) VerifyRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) error {
	if a.disablePolicyd {
		return nil
	}

	drcheck := make(map[string]struct{})
	domainRoles := make(map[string][]string)
	addDomainRoles := func(dr []string) {
		if len(dr) != 2 {
			return
		}
		domain, roleName := dr[0], dr[1]
		// duplicated role check
		if _, ok := drcheck[domain+roleName]; !ok {
			domainRoles[domain] = append(domainRoles[domain], roleName)
			drcheck[domain+roleName] = struct{}{}
		}
	}

	for _, cert := range peerCerts {
		subj := cert.Subject.CommonName
		dr := strings.SplitN(subj, roleInCNDelimiter, 2)
		// dr will be just ignored when subj doesn't represents a role (not contains ":role.")
		addDomainRoles(dr)

		for _, uri := range cert.URIs {
			if strings.HasPrefix(uri.String(), a.roleCertURIPrefix) {
				dr := strings.SplitN(strings.TrimPrefix(uri.String(), a.roleCertURIPrefix), "/", 2) // domain/role
				addDomainRoles(dr)
			}
		}
	}

	if len(domainRoles) == 0 {
		return errors.New("invalid role certificate")
	}

	var err error
	for domain, roles := range domainRoles {
		// TODO futurework
		if err = a.policyd.CheckPolicy(ctx, domain, roles, act, res); err == nil {
			return nil
		}
	}

	return errors.Wrap(err, "role certificates unauthorized")
}

// AuthorizeRoleCert verifies the role certificate for specific resource and returns the result of verifying or verification error if unauthorized. (unimplemented)
func (a *authority) AuthorizeRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) (Principal, error) {
	// TODO VerifyRoleCert has not yet been implemented to return a Principal
	return nil, errors.New("AuthorizeRoleCert has not yet been implemented")
}

// GetPolicyCache returns the cached policy data
func (a *authority) GetPolicyCache(ctx context.Context) map[string][]*policy.Assertion {
	if !a.disablePolicyd {
		return a.policyd.GetPolicyCache(ctx)
	} else {
		return make(map[string][]*policy.Assertion)
	}
}
