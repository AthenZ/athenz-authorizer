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
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AthenZ/athenz-authorizer/v5/access"
	"github.com/AthenZ/athenz-authorizer/v5/jwk"
	"github.com/AthenZ/athenz-authorizer/v5/policy"
	"github.com/AthenZ/athenz-authorizer/v5/pubkey"
	"github.com/AthenZ/athenz-authorizer/v5/role"
	"github.com/golang-jwt/jwt/v4"
	"github.com/kpango/fastime"
	"github.com/kpango/gache/v2"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Authorizerd, error) error
	}{
		{
			name: "test New success",
			args: args{
				[]Option{},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				if err != nil {
					return errors.Wrap(err, "unexpected error")
				}
				if prov.(*authority).athenzURL != "athenz.io/zts/v1" {
					return errors.New("invalid url")
				}
				if prov.(*authority).pubkeyd == nil {
					return errors.New("cannot new pubkeyd")
				}
				if prov.(*authority).policyd == nil {
					return errors.New("cannot new policyd")
				}
				if prov.(*authority).jwkd == nil {
					return errors.New("cannot new jwkd")
				}
				return nil
			},
		},
		{
			name: "test New success, disable jwkd",
			args: args{
				[]Option{WithDisableJwkd()},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				if err != nil {
					return errors.Wrap(err, "unexpected error")
				}
				if prov.(*authority).athenzURL != "athenz.io/zts/v1" {
					return errors.New("invalid url")
				}
				if prov.(*authority).pubkeyd == nil {
					return errors.New("cannot new pubkeyd")
				}
				if prov.(*authority).policyd == nil {
					return errors.New("cannot new policyd")
				}
				if prov.(*authority).jwkd != nil {
					return errors.New("cannot disable jwkd")
				}
				return nil
			},
		},
		{
			name: "test New success with options",
			args: args{
				[]Option{WithAthenzURL("www.dummy.com")},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				if err != nil {
					return errors.Wrap(err, "unexpected error")
				}
				if prov.(*authority).athenzURL != "www.dummy.com" {
					return errors.New("invalid url")
				}
				return nil
			},
		},
		{
			name: "test New error, public key",
			args: args{
				[]Option{WithPubkeyRefreshPeriod("dummy")},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				wantErr := "error create pubkeyd: invalid refresh period: time: invalid duration \"dummy\""
				if err.Error() != wantErr {
					return errors.Errorf("Unexpected error: %s, wantErr: %s", err, wantErr)
				}
				return nil
			},
		},
		{
			name: "test New error, policy",
			args: args{
				[]Option{WithPolicyRefreshPeriod("dummy")},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				wantErr := "error create policyd: invalid refresh period: time: invalid duration \"dummy\""
				if err.Error() != wantErr {
					return errors.Errorf("Unexpected error: %s, wantErr: %s", err, wantErr)
				}
				return nil
			},
		},
		{
			name: "test New error, jwk",
			args: args{
				[]Option{WithJwkRefreshPeriod("dummy")},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				wantErr := "error create jwkd: invalid refresh period: time: invalid duration \"dummy\""
				if err.Error() != wantErr {
					return errors.Errorf("Unexpected error: %s, wantErr: %s", err, wantErr)
				}
				return nil
			},
		},
		{
			name: "test New error, access token",
			args: args{
				[]Option{
					WithAccessTokenParam(NewAccessTokenParam(true, false, "dummy", "dummy", false, nil)),
				},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				wantErr := "error create access token processor: invalid refresh period: time: invalid duration \"dummy\""
				if err.Error() != wantErr {
					return errors.Errorf("Unexpected error: %s, wantErr: %s", err, wantErr)
				}
				return nil
			},
		},
		{
			name: "test New error, authorizer",
			args: args{
				[]Option{
					WithDisableRoleToken(),
					WithDisableRoleCert(),
					WithAccessTokenParam(NewAccessTokenParam(false, false, "", "", false, nil)),
				},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				wantErr := "error create authorizers: error no authorizers"
				if err.Error() != wantErr {
					return errors.Errorf("Unexpected error: %s, wantErr: %s", err, wantErr)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := New(tt.args.opts...)
			if err := tt.checkFunc(got, gotErr); err != nil {
				t.Errorf("New() error = %v", err)
			}
		})
	}
}

func Test_authorizer_initAuthorizers(t *testing.T) {
	type fields struct {
		authorizers           []authorizer
		athenzURL             string
		client                *http.Client
		cache                 gache.Gache[Principal]
		cacheExp              time.Duration
		roleCertURIPrefix     string
		disablePubkeyd        bool
		pubkeyRefreshPeriod   string
		pubkeyRetryDelay      string
		pubkeySysAuthDomain   string
		pubkeyETagExpiry      string
		pubkeyETagPurgePeriod string
		disablePolicyd        bool
		policyExpiryMargin    string
		athenzDomains         []string
		policyRefreshPeriod   string
		policyRetryDelay      string
		policyRetryAttempts   int
		disableJwkd           bool
		jwkRefreshPeriod      string
		jwkRetryDelay         string
		accessTokenParam      AccessTokenParam
		enableRoleToken       bool
		roleAuthHeader        string
		enableRoleCert        bool
	}
	tests := []struct {
		name      string
		fields    fields
		wantErr   bool
		checkFunc func(a authority) error
	}{
		{
			name: "initVerifier success, no role flags",
			fields: fields{
				accessTokenParam: AccessTokenParam{enable: true, verifyCertThumbprint: true},
				enableRoleCert:   false,
				enableRoleToken:  false,
			},
			wantErr: false,
			checkFunc: func(a authority) error {
				if len(a.authorizers) != 1 {
					return errors.New("failed init authorizer")
				}
				return nil
			},
		},
		{
			name: "initVerifier success, no access token flags",
			fields: fields{
				enableRoleCert: true,
			},
			wantErr: false,
			checkFunc: func(a authority) error {
				if len(a.authorizers) != 1 {
					return errors.New("failed init authorizer")
				}
				return nil
			},
		},
		{
			name: "initVerifier success, no access token flags",
			fields: fields{
				enableRoleCert:  true,
				enableRoleToken: true,
			},
			wantErr: false,
			checkFunc: func(a authority) error {
				if len(a.authorizers) != 2 {
					return errors.New("failed init authorizer")
				}
				return nil
			},
		},
		{
			name:    "initVerifier fail, no authorizers",
			fields:  fields{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authority{
				authorizers:           tt.fields.authorizers,
				athenzURL:             tt.fields.athenzURL,
				client:                tt.fields.client,
				cache:                 tt.fields.cache,
				cacheExp:              tt.fields.cacheExp,
				roleCertURIPrefix:     tt.fields.roleCertURIPrefix,
				disablePubkeyd:        tt.fields.disablePubkeyd,
				pubkeyRefreshPeriod:   tt.fields.pubkeyRefreshPeriod,
				pubkeyRetryDelay:      tt.fields.pubkeyRetryDelay,
				pubkeySysAuthDomain:   tt.fields.pubkeySysAuthDomain,
				pubkeyETagExpiry:      tt.fields.pubkeyETagExpiry,
				pubkeyETagPurgePeriod: tt.fields.pubkeyETagPurgePeriod,
				disablePolicyd:        tt.fields.disablePolicyd,
				policyExpiryMargin:    tt.fields.policyExpiryMargin,
				athenzDomains:         tt.fields.athenzDomains,
				policyRefreshPeriod:   tt.fields.policyRefreshPeriod,
				policyRetryDelay:      tt.fields.policyRetryDelay,
				policyRetryAttempts:   tt.fields.policyRetryAttempts,
				disableJwkd:           tt.fields.disableJwkd,
				jwkRefreshPeriod:      tt.fields.jwkRefreshPeriod,
				jwkRetryDelay:         tt.fields.jwkRetryDelay,
				accessTokenParam:      tt.fields.accessTokenParam,
				enableRoleToken:       tt.fields.enableRoleToken,
				roleAuthHeader:        tt.fields.roleAuthHeader,
				enableRoleCert:        tt.fields.enableRoleCert,
			}
			if err := a.initAuthorizers(); (err != nil) != tt.wantErr {
				t.Errorf("authority.initAuthorizers() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(*a); err != nil {
					t.Errorf("VerifyRoleToken() error: %v", err)
				}
			}
		})
	}
}
func Test_authorizer_Init(t *testing.T) {
	type fields struct {
		pubkeyd        pubkey.Daemon
		policyd        policy.Daemon
		jwkd           jwk.Daemon
		disablePubkeyd bool
		disablePolicyd bool
		disableJwkd    bool
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErrStr string
	}{
		{
			name: "cancelled context, no waiting",
			fields: fields{
				pubkeyd: &PubkeydMock{
					UpdateFunc: func(context.Context) error {
						time.Sleep(10 * time.Millisecond)
						return errors.New("pubkeyd error")
					},
				},
				policyd: nil,
				jwkd: &JwkdMock{
					UpdateFunc: func(context.Context) error {
						time.Sleep(10 * time.Millisecond)
						return errors.New("jwkd error")
					},
				},
				disablePubkeyd: false,
				disablePolicyd: true,
				disableJwkd:    false,
			},
			args: args{
				ctx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return ctx
				}(),
			},
			wantErrStr: context.Canceled.Error(),
		},
		{
			name: "all disable",
			fields: fields{
				pubkeyd:        nil,
				policyd:        nil,
				jwkd:           nil,
				disablePubkeyd: true,
				disablePolicyd: true,
				disableJwkd:    true,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErrStr: "",
		},
		{
			name: "jwkd is not blocked",
			fields: fields{
				pubkeyd: &PubkeydMock{
					UpdateFunc: func(context.Context) error {
						time.Sleep(10 * time.Millisecond)
						return errors.New("pubkeyd error")
					},
				},
				policyd: nil,
				jwkd: &JwkdMock{
					UpdateFunc: func(context.Context) error {
						return errors.New("jwkd done")
					},
				},
				disablePubkeyd: false,
				disablePolicyd: true,
				disableJwkd:    false,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErrStr: "jwkd done",
		},
		{
			name: "policyd is blocked by pubkeyd",
			fields: *(func() *fields {
				pubkeydDone := false
				return &fields{
					pubkeyd: &PubkeydMock{
						UpdateFunc: func(context.Context) error {
							time.Sleep(10 * time.Millisecond)
							pubkeydDone = true
							return nil
						},
					},
					policyd: &PolicydMock{
						UpdateFunc: func(context.Context) error {
							if pubkeydDone {
								return nil
							}
							return errors.New("policyd error")
						},
					},
					jwkd:           nil,
					disablePubkeyd: false,
					disablePolicyd: true,
					disableJwkd:    true,
				}
			}()),
			args: args{
				ctx: context.Background(),
			},
			wantErrStr: "",
		},
		{
			name: "all daemons init success",
			fields: fields{
				pubkeyd: &PubkeydMock{
					UpdateFunc: func(context.Context) error {
						return nil
					},
				},
				policyd: &PolicydMock{
					UpdateFunc: func(context.Context) error {
						return nil
					},
				},
				jwkd: &JwkdMock{
					UpdateFunc: func(context.Context) error {
						return nil
					},
				},
				disablePubkeyd: false,
				disablePolicyd: false,
				disableJwkd:    false,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErrStr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authority{
				pubkeyd:        tt.fields.pubkeyd,
				policyd:        tt.fields.policyd,
				jwkd:           tt.fields.jwkd,
				disablePubkeyd: tt.fields.disablePubkeyd,
				disablePolicyd: tt.fields.disablePolicyd,
				disableJwkd:    tt.fields.disableJwkd,
			}
			err := a.Init(tt.args.ctx)
			if (err == nil && tt.wantErrStr != "") || (err != nil && err.Error() != tt.wantErrStr) {
				t.Errorf("authority.Init() error = %v, wantErr %v", err, tt.wantErrStr)
				return
			}
		})
	}
}

func Test_authorizer_Start(t *testing.T) {
	type fields struct {
		pubkeyd  pubkey.Daemon
		policyd  policy.Daemon
		jwkd     jwk.Daemon
		cache    gache.Gache[Principal]
		cacheExp time.Duration
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(Authorizerd, error) error
		afterFunc func()
	}
	tests := []test{
		func() test {
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Millisecond*10))
			pdm := &ConfdMock{
				confdExp: time.Second,
			}
			pm := &PolicydMock{
				policydExp: time.Second,
			}
			jd := &JwkdMock{}
			return test{
				name: "test context done",
				fields: fields{
					pubkeyd:  pdm,
					policyd:  pm,
					jwkd:     jd,
					cache:    gache.New[Principal](),
					cacheExp: time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Authorizerd, err error) error {
					if err.Error() != "context deadline exceeded" {
						return errors.Wrap(err, "unexpected err")
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Second))
			pdm := &ConfdMock{
				confdExp: time.Millisecond * 10,
			}
			pm := &PolicydMock{
				policydExp: time.Second,
			}
			jd := &JwkdMock{}
			return test{
				name: "test context pubkey updater returns error",
				fields: fields{
					pubkeyd:  pdm,
					policyd:  pm,
					jwkd:     jd,
					cache:    gache.New[Principal](),
					cacheExp: time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Authorizerd, err error) error {
					if err.Error() != "update pubkey error: pubkey error" {
						return errors.Wrap(err, "unexpected err")
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Second))
			pdm := &ConfdMock{
				confdExp: time.Second,
			}
			pm := &PolicydMock{
				policydExp: time.Millisecond * 10,
			}
			jd := &JwkdMock{}
			return test{
				name: "test policyd returns error",
				fields: fields{
					pubkeyd:  pdm,
					policyd:  pm,
					jwkd:     jd,
					cache:    gache.New[Principal](),
					cacheExp: time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Authorizerd, err error) error {
					if err.Error() != "update policy error: policyd error" {
						return errors.Wrap(err, "unexpected err")
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Millisecond*500))
			pdm := &ConfdMock{
				confdExp: time.Second,
			}
			pm := &PolicydMock{
				policydExp: time.Second,
			}
			jd := &JwkdMock{
				StartFunc: func(ctx context.Context) <-chan error {
					ch := make(chan error, 1)
					go func() {
						time.Sleep(time.Millisecond * 20)
						ch <- errors.New("dummy")
					}()
					return ch
				},
			}
			return test{
				name: "test jwkd returns error",
				fields: fields{
					pubkeyd:  pdm,
					policyd:  pm,
					jwkd:     jd,
					cache:    gache.New[Principal](),
					cacheExp: time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Authorizerd, err error) error {
					if err.Error() != "update jwk error: dummy" {
						return errors.Errorf("unexpected error: %s", err)
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := &authority{
				pubkeyd:  tt.fields.pubkeyd,
				policyd:  tt.fields.policyd,
				jwkd:     tt.fields.jwkd,
				cache:    tt.fields.cache,
				cacheExp: tt.fields.cacheExp,
			}
			ch := prov.Start(tt.args.ctx)
			gotErr := <-ch
			if err := tt.checkFunc(prov, gotErr); err != nil {
				t.Errorf("Start() error = %v", err)
			}
			tt.afterFunc()
		})
	}
}

func Test_authorizer_AuthorizeRoleToken(t *testing.T) {
	type args struct {
		ctx context.Context
		tok string
		act string
		res string
	}
	type fields struct {
		policyd            policy.Daemon
		cache              gache.Gache[Principal]
		cacheExp           time.Duration
		roleTokenProcessor role.Processor
		cacheMemoryUsage   *atomic.Int64
	}
	type test struct {
		name       string
		args       args
		fields     fields
		wantErr    string
		wantResult Principal
		checkFunc  func(*authority) error
	}
	tests := []test{
		func() test {
			c := gache.New[Principal]()
			rt := &role.Token{}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test verify success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: rpm,
					cache:              c,
					cacheExp:           time.Minute,
					cacheMemoryUsage:   &atomic.Int64{},
				},
				wantErr:    "",
				wantResult: p,
				checkFunc: func(prov *authority) error {
					_, ok := prov.cache.Get("dummyTok:dummyAct:dummyRes")
					if !ok {
						return errors.New("cannot get dummyTok:dummyAct:dummyRes from cache")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			rt := &role.Token{}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			c.Set("dummyTok:dummyAct:dummyRes", p)
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test use cache success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: rpm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr:    "",
				wantResult: p,
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			c.Set("dummyTok:dummyAct:dummyRes", &principal{})
			rpm := &RoleProcessorMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty action",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: rpm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			c.Set("dummyTok:dummyAct:dummyRes", &principal{})
			rpm := &RoleProcessorMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty res",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: rpm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			rpm := &RoleProcessorMock{
				wantErr: errors.New("cannot parse roletoken"),
			}
			pdm := &PolicydMock{}
			return test{
				name: "test parse roletoken error",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: rpm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "error authorize role token: cannot parse roletoken",
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			rpm := &RoleProcessorMock{
				rt: &role.Token{},
			}
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(context.Context, string, []string, string, string) ([]string, error) {
					return nil, errors.New("deny")
				},
			}
			return test{
				name: "test return deny",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: rpm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "token unauthorized: deny",
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := &authority{
				policyd:          tt.fields.policyd,
				roleProcessor:    tt.fields.roleTokenProcessor,
				cache:            tt.fields.cache,
				cacheExp:         tt.fields.cacheExp,
				cacheMemoryUsage: tt.fields.cacheMemoryUsage,
			}
			err := prov.VerifyRoleToken(tt.args.ctx, tt.args.tok, tt.args.act, tt.args.res)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("VerifyRoleToken() unexpected error want:%s, result:%s", tt.wantErr, err.Error())
					return
				}
			} else {
				if tt.wantErr != "" {
					t.Errorf("VerifyRoleToken() return nil. want %s", tt.wantErr)
					return
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(prov); err != nil {
					t.Errorf("VerifyRoleToken() error: %v", err)
				}
			}

			p, err := prov.AuthorizeRoleToken(tt.args.ctx, tt.args.tok, tt.args.act, tt.args.res)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("AuthorizeRoleToken() unexpected error want:%s, result:%s", tt.wantErr, err.Error())
					return
				}
			} else {
				if tt.wantErr != "" {
					t.Errorf("AuthorizeRoleToken() return nil. want %s", tt.wantErr)
					return
				}
				if !reflect.DeepEqual(p, tt.wantResult) {
					t.Errorf("AuthorizeRoleToken() results don't match. want %s, result %s", tt.wantResult, p)
					return
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(prov); err != nil {
					t.Errorf("AuthorizeRoleToken() error: %v", err)
				}
			}
		})
	}
}

func Test_authorizer_authorize(t *testing.T) {
	type fields struct {
		pubkeyd                      pubkey.Daemon
		policyd                      policy.Daemon
		jwkd                         jwk.Daemon
		roleProcessor                role.Processor
		athenzURL                    string
		client                       *http.Client
		cache                        gache.Gache[Principal]
		cacheExp                     time.Duration
		roleCertURIPrefix            string
		pubkeyRefreshPeriod          string
		pubkeySysAuthDomain          string
		pubkeyETagExpiry             string
		pubkeyETagPurgePeriod        string
		policyExpiryMargin           string
		athenzDomains                []string
		policyRefreshPeriod          string
		disablePolicyd               bool
		translator                   Translator
		resourcePrefix               string
		cacheMemoryUsage             *atomic.Int64
		outputAuthorizedPrincipalLog bool
	}
	type args struct {
		ctx   context.Context
		m     mode
		tok   string
		act   string
		res   string
		query string
		cert  *x509.Certificate
	}
	type test struct {
		name       string
		fields     fields
		args       args
		wantErr    bool
		wantResult Principal
		checkFunc  func(prov *authority, buf *bytes.Buffer) error
	}
	tests := []test{
		func() test {
			c := gache.New[Principal]()
			var count int
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, action, resource string) ([]string, error) {
					count++
					return roles, nil
				},
			}
			rt := &role.Token{}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			return test{
				name: "test disablePolicyd true",
				fields: fields{
					cache:            c,
					policyd:          pdm,
					disablePolicyd:   true,
					roleProcessor:    rpm,
					cacheMemoryUsage: &atomic.Int64{},
				},
				args: args{
					m:   roleToken,
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					if count != 0 {
						return errors.New("CheckPolicy must not be called")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			pdm := &PolicydMock{}
			rt := &role.Token{}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			return test{
				name: "test cache key when disablePolicyd is true",
				fields: fields{
					cache:            c,
					policyd:          pdm,
					disablePolicyd:   true,
					roleProcessor:    rpm,
					cacheMemoryUsage: &atomic.Int64{},
				},
				args: args{
					m:   roleToken,
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					_, ok := prov.cache.Get("dummyTok")
					if !ok {
						return errors.New("cannot get dummyTok from cache")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			pdm := &PolicydMock{}
			rt := &role.Token{}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			return test{
				name: "test cache key when disablePolicyd is false",
				fields: fields{
					cache:            c,
					policyd:          pdm,
					disablePolicyd:   false,
					roleProcessor:    rpm,
					cacheMemoryUsage: &atomic.Int64{},
				},
				args: args{
					m:   roleToken,
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					_, ok := prov.cache.Get("dummyTok:dummyAct:dummyRes")
					if !ok {
						return errors.New("cannot get dummyTok:dummyAct:dummyRes from cache")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			pdm := &PolicydMock{}
			rt := &role.Token{
				Domain: "domain",
			}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			mr, _ := NewMappingRules(map[string][]Rule{
				"domain": {{
					Method:   "get",
					Path:     "/path?param=value",
					Action:   "dummyAct",
					Resource: "dummyRes",
				}},
			})
			return test{
				name: "test cache key when disablePolicyd is false and translator is not nil",
				fields: fields{
					cache:            c,
					policyd:          pdm,
					disablePolicyd:   false,
					roleProcessor:    rpm,
					translator:       mr,
					cacheMemoryUsage: &atomic.Int64{},
				},
				args: args{
					m:     roleToken,
					ctx:   context.Background(),
					tok:   "dummyTok",
					act:   "get",
					res:   "/path",
					query: "param=value",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					_, ok := prov.cache.Get("dummyTok:get:/path:param=value")
					if !ok {
						return errors.New("cannot get dummyTok:get:/path:param=value from cache")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			pdm := &PolicydMock{}
			rt := &role.Token{
				Domain: "domain",
			}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			mr, _ := NewMappingRules(map[string][]Rule{
				"domain1": {{
					Method:   "get",
					Path:     "/path?param=value",
					Action:   "dummyAct",
					Resource: "dummyRes",
				}},
			})
			return test{
				name: "test cache key when disablePolicyd is false and translator is not nil, but didn't match",
				fields: fields{
					cache:            c,
					policyd:          pdm,
					disablePolicyd:   false,
					roleProcessor:    rpm,
					translator:       mr,
					cacheMemoryUsage: &atomic.Int64{},
				},
				args: args{
					m:     roleToken,
					ctx:   context.Background(),
					tok:   "dummyTok",
					act:   "get",
					res:   "/path",
					query: "param=value",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					_, ok := prov.cache.Get("dummyTok:get:/path:param=value")
					if !ok {
						return errors.New("cannot get dummyTok:get:/path:param=value from cache")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			pdm := &PolicydMock{}
			rt := &role.Token{
				Domain: "domain",
			}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			return test{
				name: "test cache key when disablePolicyd is false and translator is nil",
				fields: fields{
					cache:            c,
					policyd:          pdm,
					disablePolicyd:   false,
					roleProcessor:    rpm,
					cacheMemoryUsage: &atomic.Int64{},
				},
				args: args{
					m:     roleToken,
					ctx:   context.Background(),
					tok:   "dummyTok",
					act:   "get",
					res:   "/path",
					query: "param=value",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					_, ok := prov.cache.Get("dummyTok:get:/path")
					if !ok {
						return errors.New("cannot get dummyTok:get:/path from cache")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, action, resource string) ([]string, error) {
					if resource != "/public/path" {
						return nil, errors.New("unexpected resource, got: " + resource)
					}
					return roles, nil
				},
			}
			rt := &role.Token{
				Domain: "domain",
			}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			return test{
				name: "test resourcePrefix",
				fields: fields{
					cache:            c,
					policyd:          pdm,
					disablePolicyd:   false,
					roleProcessor:    rpm,
					resourcePrefix:   "/public",
					cacheMemoryUsage: &atomic.Int64{},
				},
				args: args{
					m:     roleToken,
					ctx:   context.Background(),
					tok:   "dummyTok",
					act:   "get",
					res:   "/path",
					query: "param=value",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					return nil
				},
			}
		}(),
		func() test {
			buf := new(bytes.Buffer)
			glg.Get().SetMode(glg.WRITER).SetWriter(buf)

			c := gache.New[Principal]()
			pdm := &PolicydMock{}
			rt := &role.Token{}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			return test{
				name: "test outputAuthorizedPrincipalLog true",
				fields: fields{
					cache:                        c,
					policyd:                      pdm,
					roleProcessor:                rpm,
					disablePolicyd:               false,
					cacheMemoryUsage:             &atomic.Int64{},
					outputAuthorizedPrincipalLog: true,
				},
				args: args{
					m:   roleToken,
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					logged := buf.String()

					if !strings.Contains(logged, "access authorized, principal:") {
						return errors.New(logged)
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			pdm := &PolicydMock{}
			rt := &role.Token{}
			p := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			c.Set("dummyTok:dummyAct:dummyRes", p)
			rpm := &RoleProcessorMock{
				rt:      rt,
				wantErr: nil,
			}
			return test{
				name: "test outputAuthorizedPrincipalLog true when cache hit",
				fields: fields{
					cache:                        c,
					policyd:                      pdm,
					roleProcessor:                rpm,
					disablePolicyd:               false,
					cacheMemoryUsage:             &atomic.Int64{},
					outputAuthorizedPrincipalLog: true,
				},
				args: args{
					m:   roleToken,
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				wantErr:    false,
				wantResult: p,
				checkFunc: func(prov *authority, buf *bytes.Buffer) error {
					logged := buf.String()

					if !strings.Contains(logged, "access authorized by cache, principal:") {
						return errors.New("expected log message not found")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			glg.Get().SetMode(glg.WRITER).SetWriter(buf)

			a := &authority{
				pubkeyd:                      tt.fields.pubkeyd,
				policyd:                      tt.fields.policyd,
				jwkd:                         tt.fields.jwkd,
				roleProcessor:                tt.fields.roleProcessor,
				athenzURL:                    tt.fields.athenzURL,
				client:                       tt.fields.client,
				cache:                        tt.fields.cache,
				cacheExp:                     tt.fields.cacheExp,
				roleCertURIPrefix:            tt.fields.roleCertURIPrefix,
				pubkeyRefreshPeriod:          tt.fields.pubkeyRefreshPeriod,
				pubkeySysAuthDomain:          tt.fields.pubkeySysAuthDomain,
				pubkeyETagExpiry:             tt.fields.pubkeyETagExpiry,
				pubkeyETagPurgePeriod:        tt.fields.pubkeyETagPurgePeriod,
				policyExpiryMargin:           tt.fields.policyExpiryMargin,
				athenzDomains:                tt.fields.athenzDomains,
				policyRefreshPeriod:          tt.fields.policyRefreshPeriod,
				disablePolicyd:               tt.fields.disablePolicyd,
				translator:                   tt.fields.translator,
				resourcePrefix:               tt.fields.resourcePrefix,
				cacheMemoryUsage:             tt.fields.cacheMemoryUsage,
				outputAuthorizedPrincipalLog: tt.fields.outputAuthorizedPrincipalLog,
			}
			p, err := a.authorize(tt.args.ctx, tt.args.m, tt.args.tok, tt.args.act, tt.args.res, tt.args.query, tt.args.cert)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("authority.authorize() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			} else {
				if !reflect.DeepEqual(p, tt.wantResult) {
					t.Errorf("authority.authorize() results don't match. result %v, wantResult %v", p, tt.wantResult)
					return
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(a, buf); err != nil {
					t.Errorf("authority.authorize() error: %v", err)
				}
			}

			buf.Reset()
		})
	}
}

func Test_authorizer_principalCacheMemoryUsage(t *testing.T) {
	type args struct {
		key string
		p   Principal
	}
	type test struct {
		name string
		args args
		want int64
	}
	tests := []test{
		func() test {
			rt := &role.Token{
				Principal:  "dummyPrincipal",
				Roles:      []string{"dummyRole"},
				Domain:     "dummyDomain",
				TimeStamp:  time.Now(),
				ExpiryTime: time.Now().Add(time.Hour),
			}
			pc := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			return test{
				name: "principalCacheMemoryUsage return correct principal memory usage for role token",
				args: args{
					key: "dummyKey",
					p:   pc,
				},
				want: 170,
			}
		}(),
		func() test {
			at := &access.OAuth2AccessTokenClaim{
				Scope: []string{"role"},
				BaseClaim: access.BaseClaim{
					StandardClaims: jwt.StandardClaims{
						Audience: "domain",
					},
				},
			}
			pc := &oAuthAccessToken{
				principal: principal{
					name:            at.BaseClaim.Subject,
					roles:           at.Scope,
					domain:          at.BaseClaim.Audience,
					issueTime:       at.IssuedAt,
					expiryTime:      at.ExpiresAt,
					authorizedRoles: []string{"role"},
				},
				clientID: at.ClientID,
			}
			return test{
				name: "principalCacheMemoryUsage return correct principal memory usage for access token",
				args: args{
					key: "dummyKey",
					p:   pc,
				},
				want: 166,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := principalCacheMemoryUsage(tt.args.key, tt.args.p)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authorizerd.principalCacheMemoryUsage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authorizer_VerifyRoleCert(t *testing.T) {
	type fields struct {
		pubkeyd               pubkey.Daemon
		policyd               policy.Daemon
		jwkd                  jwk.Daemon
		roleProcessor         role.Processor
		athenzURL             string
		client                *http.Client
		cache                 gache.Gache[Principal]
		cacheExp              time.Duration
		roleCertURIPrefix     string
		pubkeyRefreshPeriod   string
		pubkeySysAuthDomain   string
		pubkeyETagExpiry      string
		pubkeyETagPurgePeriod string
		policyExpiryMargin    string
		athenzDomains         []string
		policyRefreshPeriod   string
		disablePolicyd        bool
	}
	type args struct {
		ctx       context.Context
		peerCerts []*x509.Certificate
		act       string
		res       string
	}
	type test struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}
	tests := []test{
		func() test {
			crt := `-----BEGIN CERTIFICATE-----
MIICGTCCAcOgAwIBAgIJALLML3PdJAZ1MA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJDQTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5U
ZXN0aW5nIERvbWFpbjEWMBQGA1UEAxMNYXRoZW56LnN5bmNlcjAeFw0xOTA0Mjcw
MjQ2MjNaFw0yOTA0MjQwMjQ2MjNaMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5UZXN0aW5nIERvbWFpbjEWMBQG
A1UEAxMNYXRoZW56LnN5bmNlcjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvv27a
SNAnK0vcN8fqqQgMHwb0EhfVWMwoRTBQFrCmA9mH/84QgI/0kR3ZI+DlDNBCgDHd
rEJZVPyX2V41VOX3AgMBAAGjaDBmMGQGA1UdEQRdMFuGGXNwaWZmZTovL2F0aGVu
ei9zYS9zeW5jZXKGHmF0aGVuejovL3JvbGUvY29yZXRlY2gvcmVhZGVyc4YeYXRo
ZW56Oi8vcm9sZS9jb3JldGVjaC93cml0ZXJzMA0GCSqGSIb3DQEBCwUAA0EAa3Ra
Wo7tEDFBGqSVYSVuoh0GpsWC0VBAYYi9vhAGfp+g5M2oszvRuxOHYsQmYAjYroTJ
bu80CwTnWhmdBo36Ig==
-----END CERTIFICATE-----`
			block, _ := pem.Decode([]byte(crt))
			cert, _ := x509.ParseCertificate(block.Bytes)

			pm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, act, res string) ([]string, error) {
					containRole := func(r string) bool {
						for _, role := range roles {
							if role == r {
								return true
							}
						}
						return false
					}
					if domain != "coretech" {
						return nil, errors.Errorf("invalid domain, got: %s, want: %s", domain, "coretech")
					}
					if !containRole("readers") || !containRole("writers") {
						return nil, errors.Errorf("invalid role, got: %s", roles)
					}
					return nil, nil
				},
			}

			return test{
				name: "parse and verify role cert success",
				fields: fields{
					roleCertURIPrefix: "athenz://role/",
					policyd:           pm,
				},
				args: args{
					ctx: context.Background(),
					peerCerts: []*x509.Certificate{
						cert,
					},
					act: "abc",
					res: "def",
				},
			}
		}(),
		func() test {
			crt := `
-----BEGIN CERTIFICATE-----
MIICLjCCAZegAwIBAgIBADANBgkqhkiG9w0BAQ0FADA0MQswCQYDVQQGEwJ1czEL
MAkGA1UECAwCSEsxCzAJBgNVBAoMAkhLMQswCQYDVQQDDAJISzAeFw0xOTA3MDQw
NjU2MTJaFw0yMDA3MDMwNjU2MTJaMDQxCzAJBgNVBAYTAnVzMQswCQYDVQQIDAJI
SzELMAkGA1UECgwCSEsxCzAJBgNVBAMMAkhLMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQDdUHpdYo/UeYvzB4Z3WvUe2yHsuxrhh7x/D2A5OPb19+ZZy4cdMDUW
qd3hw/tvBWxSUYueL75AifVAQdncUJ+7of3WByFYVSemDrdlD9K/+PyGFZotA+Xj
GmNWjAsGBYuU5roxJZI2c78vJzKj2DU1a9hq/PJ9WGvX4i1Xwf0FKwIDAQABo1Aw
TjAdBgNVHQ4EFgQUiLEo7+nigzdGft2ZEbpkZFxgU+MwHwYDVR0jBBgwFoAUiLEo
7+nigzdGft2ZEbpkZFxgU+MwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOB
gQCiedWe2DXuE0ak1oGV+28qLpyc/Ff9RNNwUbCKB6L/+OWoROVdaz/DoZjfE9vr
ilcIAqkugYyMzW4cY2RexOLYrkyyjLjMj5C2ff4m13gqRLHU0rFpaKpjYr8KYiGD
KSdPh6TRd/kYpv7t6cVm1Orll4O5jh+IdoguGkOCxheMaQ==
-----END CERTIFICATE-----`
			block, _ := pem.Decode([]byte(crt))
			cert, _ := x509.ParseCertificate(block.Bytes)

			pm := &PolicydMock{}

			return test{
				name: "invalid athenz role certificate, invalid SAN",
				fields: fields{
					roleCertURIPrefix: "athenz://role/",
					policyd:           pm,
				},
				args: args{
					ctx: context.Background(),
					peerCerts: []*x509.Certificate{
						cert,
					},
					act: "abc",
					res: "def",
				},
				wantErr: true,
			}
		}(),
		func() test {
			crt := `-----BEGIN CERTIFICATE-----
MIICGTCCAcOgAwIBAgIJALLML3PdJAZ1MA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJDQTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5U
ZXN0aW5nIERvbWFpbjEWMBQGA1UEAxMNYXRoZW56LnN5bmNlcjAeFw0xOTA0Mjcw
MjQ2MjNaFw0yOTA0MjQwMjQ2MjNaMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5UZXN0aW5nIERvbWFpbjEWMBQG
A1UEAxMNYXRoZW56LnN5bmNlcjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvv27a
SNAnK0vcN8fqqQgMHwb0EhfVWMwoRTBQFrCmA9mH/84QgI/0kR3ZI+DlDNBCgDHd
rEJZVPyX2V41VOX3AgMBAAGjaDBmMGQGA1UdEQRdMFuGGXNwaWZmZTovL2F0aGVu
ei9zYS9zeW5jZXKGHmF0aGVuejovL3JvbGUvY29yZXRlY2gvcmVhZGVyc4YeYXRo
ZW56Oi8vcm9sZS9jb3JldGVjaC93cml0ZXJzMA0GCSqGSIb3DQEBCwUAA0EAa3Ra
Wo7tEDFBGqSVYSVuoh0GpsWC0VBAYYi9vhAGfp+g5M2oszvRuxOHYsQmYAjYroTJ
bu80CwTnWhmdBo36Ig==
-----END CERTIFICATE-----`
			block, _ := pem.Decode([]byte(crt))
			cert, _ := x509.ParseCertificate(block.Bytes)

			pm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, act, res string) ([]string, error) {
					return nil, errors.New("dummy")
				},
			}

			return test{
				name: "invalid athenz role certificate, deny by policyd",
				fields: fields{
					roleCertURIPrefix: "athenz://role/",
					policyd:           pm,
				},
				args: args{
					ctx: context.Background(),
					peerCerts: []*x509.Certificate{
						cert,
					},
					act: "abc",
					res: "def",
				},
				wantErr: true,
			}
		}(),
		func() test {
			crt := `-----BEGIN CERTIFICATE-----
MIICGTCCAcOgAwIBAgIJALLML3PdJAZ1MA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJDQTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5U
ZXN0aW5nIERvbWFpbjEWMBQGA1UEAxMNYXRoZW56LnN5bmNlcjAeFw0xOTA0Mjcw
MjQ2MjNaFw0yOTA0MjQwMjQ2MjNaMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5UZXN0aW5nIERvbWFpbjEWMBQG
A1UEAxMNYXRoZW56LnN5bmNlcjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvv27a
SNAnK0vcN8fqqQgMHwb0EhfVWMwoRTBQFrCmA9mH/84QgI/0kR3ZI+DlDNBCgDHd
rEJZVPyX2V41VOX3AgMBAAGjaDBmMGQGA1UdEQRdMFuGGXNwaWZmZTovL2F0aGVu
ei9zYS9zeW5jZXKGHmF0aGVuejovL3JvbGUvY29yZXRlY2gvcmVhZGVyc4YeYXRo
ZW56Oi8vcm9sZS9jb3JldGVjaC93cml0ZXJzMA0GCSqGSIb3DQEBCwUAA0EAa3Ra
Wo7tEDFBGqSVYSVuoh0GpsWC0VBAYYi9vhAGfp+g5M2oszvRuxOHYsQmYAjYroTJ
bu80CwTnWhmdBo36Ig==
-----END CERTIFICATE-----`
			block, _ := pem.Decode([]byte(crt))
			cert, _ := x509.ParseCertificate(block.Bytes)

			return test{
				name: "no error if policyd is disable",
				fields: fields{
					disablePolicyd: true,
				},
				args: args{
					ctx: context.Background(),
					peerCerts: []*x509.Certificate{
						cert,
					},
				},
				wantErr: false,
			}
		}(),
		func() test {
			crt := `-----BEGIN CERTIFICATE-----
MIICPzCCAagCCQDx3uSJDnRIkDANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExDzANBgNVBAoMBkF0aGVuejEXMBUGA1UECwwOVGVzdGlu
ZyBEb21haW4xHjAcBgNVBAMMFWNvcmV0ZWNoOnJvbGUucmVhZGVyczAeFw0yMDEw
MjgwNTIwMThaFw0zMDEwMjYwNTIwMThaMGQxCzAJBgNVBAYTAlVTMQswCQYDVQQI
DAJDQTEPMA0GA1UECgwGQXRoZW56MRcwFQYDVQQLDA5UZXN0aW5nIERvbWFpbjEe
MBwGA1UEAwwVY29yZXRlY2g6cm9sZS5yZWFkZXJzMIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQDEPWOhtHIFMHhKUQbCygAFwiRjLuYA1aUKqXwq+tVLZEblE7QB
2OfyGs7ux4bSFts3O6JHlVNdYEyBGe1Ndd3mgG80SS4RTX6LngjNqT1uqnpVW8MU
QlewG1Or7C4PBflcb19CWC8UDjyip4kZ8lxD0EUz/jvn3yfAB/36Dba7vwIDAQAB
MA0GCSqGSIb3DQEBBQUAA4GBALcAGnH1CoYGZ0i2eoW621V7dNR9fggDqOZvgBz9
pGGBc0pafRYPsaZhfdhzleTpZw1iQwBf3GPmEpG1YvwzN8TfPMwPZvTTDqz0gtqI
SBg0pNnCxM0NOZaiGQ+r3+7oCpX+F3haDb4RJiagB62uFzgDlfy8cfP3tOo3Fubt
oFI/
-----END CERTIFICATE----- `
			block, _ := pem.Decode([]byte(crt))
			cert, _ := x509.ParseCertificate(block.Bytes)

			pm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, act, res string) ([]string, error) {
					containRole := func(r string) bool {
						for _, role := range roles {
							if role == r {
								return true
							}
						}
						return false
					}
					if domain != "coretech" {
						return nil, errors.Errorf("invalid domain, got: %s, want: %s", domain, "coretech")
					}
					if !containRole("readers") {
						return nil, errors.Errorf("invalid role, got: %s", roles)
					}
					return []string{"readers"}, nil
				},
			}

			return test{
				name: "parse a cert which CN indicates a role",
				fields: fields{
					policyd: pm,
				},
				args: args{
					ctx: context.Background(),
					peerCerts: []*x509.Certificate{
						cert,
					},
					act: "abc",
					res: "def",
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &authority{
				pubkeyd:               tt.fields.pubkeyd,
				policyd:               tt.fields.policyd,
				jwkd:                  tt.fields.jwkd,
				roleProcessor:         tt.fields.roleProcessor,
				athenzURL:             tt.fields.athenzURL,
				client:                tt.fields.client,
				cache:                 tt.fields.cache,
				cacheExp:              tt.fields.cacheExp,
				roleCertURIPrefix:     tt.fields.roleCertURIPrefix,
				pubkeyRefreshPeriod:   tt.fields.pubkeyRefreshPeriod,
				pubkeySysAuthDomain:   tt.fields.pubkeySysAuthDomain,
				pubkeyETagExpiry:      tt.fields.pubkeyETagExpiry,
				pubkeyETagPurgePeriod: tt.fields.pubkeyETagPurgePeriod,
				policyExpiryMargin:    tt.fields.policyExpiryMargin,
				athenzDomains:         tt.fields.athenzDomains,
				policyRefreshPeriod:   tt.fields.policyRefreshPeriod,
				disablePolicyd:        tt.fields.disablePolicyd,
			}
			if err := p.VerifyRoleCert(tt.args.ctx, tt.args.peerCerts, tt.args.act, tt.args.res); (err != nil) != tt.wantErr {
				t.Errorf("authority.VerifyRoleCert() error = %v, wantErr %v", err, tt.wantErr)
			}

			_, err := p.AuthorizeRoleCert(tt.args.ctx, tt.args.peerCerts, tt.args.act, tt.args.res)
			if err == nil {
				t.Errorf("AuthorizeRoleCert has not yet been implemented")
			}
		})
	}
}

func Test_authorizer_GetPolicyCache(t *testing.T) {
	type fields struct {
		pubkeyd               pubkey.Daemon
		policyd               policy.Daemon
		jwkd                  jwk.Daemon
		roleProcessor         role.Processor
		athenzURL             string
		client                *http.Client
		cache                 gache.Gache[Principal]
		cacheExp              time.Duration
		roleCertURIPrefix     string
		pubkeyRefreshPeriod   string
		pubkeySysAuthDomain   string
		pubkeyETagExpiry      string
		pubkeyETagPurgePeriod string
		policyExpiryMargin    string
		athenzDomains         []string
		policyRefreshPeriod   string
		disablePolicyd        bool
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string][]*policy.Assertion
	}{
		{
			name: "GetPolicyCache success",
			fields: fields{
				policyd: &PolicydMock{},
			},
			args: args{
				ctx: context.Background(),
			},
			want: nil,
		},
		{
			name: "GetPolicyCache success disable policyd",
			fields: fields{
				disablePolicyd: true,
			},
			args: args{
				ctx: context.Background(),
			},
			want: make(map[string][]*policy.Assertion),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authority{
				pubkeyd:               tt.fields.pubkeyd,
				policyd:               tt.fields.policyd,
				jwkd:                  tt.fields.jwkd,
				roleProcessor:         tt.fields.roleProcessor,
				athenzURL:             tt.fields.athenzURL,
				client:                tt.fields.client,
				cache:                 tt.fields.cache,
				cacheExp:              tt.fields.cacheExp,
				roleCertURIPrefix:     tt.fields.roleCertURIPrefix,
				pubkeyRefreshPeriod:   tt.fields.pubkeyRefreshPeriod,
				pubkeySysAuthDomain:   tt.fields.pubkeySysAuthDomain,
				pubkeyETagExpiry:      tt.fields.pubkeyETagExpiry,
				pubkeyETagPurgePeriod: tt.fields.pubkeyETagPurgePeriod,
				policyExpiryMargin:    tt.fields.policyExpiryMargin,
				athenzDomains:         tt.fields.athenzDomains,
				policyRefreshPeriod:   tt.fields.policyRefreshPeriod,
				disablePolicyd:        tt.fields.disablePolicyd,
			}
			if got := a.GetPolicyCache(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authority.GetPolicyCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authorizer_GetPrincipalCacheLen(t *testing.T) {
	type fields struct {
		cache gache.Gache[Principal]
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{
			name: "GetPrincipalCacheLen success",
			fields: fields{
				cache: gache.New[Principal](),
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authority{
				cache: tt.fields.cache,
			}
			a.cache.Set("dummyTok:dummyAct:dummyRes", &principal{})
			if got := a.GetPrincipalCacheLen(); got != tt.want {
				t.Errorf("authority.GetPrincipalCacheLen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authorizer_GetPrincipalCacheSize(t *testing.T) {
	type fields struct {
		cache            gache.Gache[Principal]
		cacheMemoryUsage *atomic.Int64
	}
	type test struct {
		name   string
		fields fields
		want   int64
	}
	tests := []test{
		func() test {
			c := gache.New[Principal]()
			return test{
				name: "GetPrincipalCacheSize return memoryUsage field",
				fields: fields{
					cache:            c,
					cacheMemoryUsage: &atomic.Int64{},
				},
				want: int64(c.Size()) + 100,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a := &authority{
				cache:            tt.fields.cache,
				cacheMemoryUsage: tt.fields.cacheMemoryUsage,
			}
			a.cacheMemoryUsage.Store(100)
			if got := a.GetPrincipalCacheSize(); got != tt.want {
				t.Errorf("authority.GetPrincipalCacheSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authorizer_cacheExpiredHook(t *testing.T) {
	type fields struct {
		ctx              context.Context
		key              string
		pc               *principal
		cache            gache.Gache[Principal]
		cacheMemoryUsage *atomic.Int64
	}
	type test struct {
		name   string
		fields fields
		want   int64
	}
	tests := []test{
		func() test {
			c := gache.New[Principal]()

			rt := &role.Token{
				Principal:  "dummyPrincipal",
				Roles:      []string{"dummyRole"},
				Domain:     "dummyDomain",
				TimeStamp:  time.Now(),
				ExpiryTime: time.Now().Add(time.Hour),
			}
			pc := &principal{
				name:       rt.Principal,
				roles:      rt.Roles,
				domain:     rt.Domain,
				issueTime:  rt.TimeStamp.Unix(),
				expiryTime: rt.ExpiryTime.Unix(),
			}
			key := "key"
			c.Set(key, pc)
			cacheUsage := principalCacheMemoryUsage(key, pc)
			cacheMemoryUsage := &atomic.Int64{}
			cacheMemoryUsage.Add(cacheUsage)
			return test{
				name: "cacheExpiredHook updating cacheMemoryUsage",
				fields: fields{
					ctx:              context.Background(),
					key:              key,
					pc:               pc,
					cache:            c,
					cacheMemoryUsage: cacheMemoryUsage,
				},
				want: 0,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a := &authority{
				cache:            tt.fields.cache,
				cacheMemoryUsage: tt.fields.cacheMemoryUsage,
			}
			a.cacheExpiredHook(tt.fields.ctx, tt.fields.key, tt.fields.pc)
			got := a.cacheMemoryUsage.Load()
			if got != tt.want {
				t.Errorf("authority.cacheExpiredHook() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authorizer_Authorize(t *testing.T) {
	type fields struct {
		authorizers []authorizer
	}
	type args struct {
		r   *http.Request
		act string
		res string
	}
	type test struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}
	tests := []test{
		{
			name: "Verify success, 1 authorizer",
			fields: fields{
				authorizers: []authorizer{
					func(r *http.Request, act, res string) (Principal, error) {
						return &principal{}, nil
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Verify success, multiple authorizer",
			fields: fields{
				authorizers: []authorizer{
					func(r *http.Request, act, res string) (Principal, error) {
						return nil, errors.Errorf("Testing verify error 1")
					},
					func(r *http.Request, act, res string) (Principal, error) {
						return &principal{}, nil
					},
					func(r *http.Request, act, res string) (Principal, error) {
						return &principal{}, nil
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Verify fail, 1 authorizer",
			fields: fields{
				authorizers: []authorizer{
					func(r *http.Request, act, res string) (Principal, error) {
						return nil, errors.Errorf("Testing verify error 1")
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Verify fail, multiple authorizer",
			fields: fields{
				authorizers: []authorizer{
					func(r *http.Request, act, res string) (Principal, error) {
						return nil, errors.Errorf("Testing verify error 1")
					},
					func(r *http.Request, act, res string) (Principal, error) {
						return nil, errors.Errorf("Testing verify error 2")
					},
					func(r *http.Request, act, res string) (Principal, error) {
						return nil, errors.Errorf("Testing verify error 3")
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authority{
				authorizers: tt.fields.authorizers,
			}
			if err := a.Verify(tt.args.r, tt.args.act, tt.args.res); (err != nil) != tt.wantErr {
				t.Errorf("authority.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if _, err := a.Authorize(tt.args.r, tt.args.act, tt.args.res); (err != nil) != tt.wantErr {
				t.Errorf("authority.Authorize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_authorizer_AuthorizeAccessToken(t *testing.T) {
	type fields struct {
		policyd          policy.Daemon
		accessProcessor  access.Processor
		cache            gache.Gache[Principal]
		cacheExp         time.Duration
		cacheMemoryUsage *atomic.Int64
	}
	type args struct {
		ctx  context.Context
		tok  string
		act  string
		res  string
		cert *x509.Certificate
	}
	type test struct {
		name       string
		fields     fields
		args       args
		wantErr    string
		wantResult Principal
		checkFunc  func(prov *authority) error
	}
	tests := []test{
		func() test {
			now := fastime.Now()
			c := gache.New[Principal]()
			at := &access.OAuth2AccessTokenClaim{
				Scope: []string{"role"},
				BaseClaim: access.BaseClaim{
					StandardClaims: jwt.StandardClaims{
						Audience: "domain",
					},
				},
			}
			p := &oAuthAccessToken{
				principal: principal{
					name:            at.BaseClaim.Subject,
					roles:           at.Scope,
					domain:          at.BaseClaim.Audience,
					issueTime:       at.IssuedAt,
					expiryTime:      at.ExpiresAt,
					authorizedRoles: []string{"role"},
				},
				clientID: at.ClientID,
			}
			apm := &AccessProcessorMock{
				atc:     at,
				wantErr: nil,
			}
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, action, resource string) ([]string, error) {
					if domain != "domain" || len(roles) != 1 || roles[0] != "role" {
						return nil, errors.New("Audience/Scope mismatch")
					}
					return []string{"role"}, nil
				},
			}
			return test{
				name: "test verify success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:          pdm,
					accessProcessor:  apm,
					cache:            c,
					cacheExp:         time.Minute,
					cacheMemoryUsage: &atomic.Int64{},
				},
				wantErr:    "",
				wantResult: p,
				checkFunc: func(prov *authority) error {
					_, expiry, ok := prov.cache.GetWithExpire("dummyTok:dummyAct:dummyRes")
					if !ok {
						return errors.New("cannot get dummyTok:dummyAct:dummyRes from cache")
					}
					wantExpiry := now.Add(time.Minute).UnixNano()
					if wantExpiry > expiry {
						return fmt.Errorf("cache expiry: got = %v, want: %v", expiry, wantExpiry)
					}
					return nil
				},
			}
		}(),
		func() test {
			now := fastime.Now()
			c := gache.New[Principal]()
			at := &access.OAuth2AccessTokenClaim{
				Scope: []string{"role"},
				BaseClaim: access.BaseClaim{
					StandardClaims: jwt.StandardClaims{
						Audience: "domain",
					},
				},
			}
			p := &oAuthAccessToken{
				principal: principal{
					name:            at.BaseClaim.Subject,
					roles:           at.Scope,
					domain:          at.BaseClaim.Audience,
					issueTime:       at.IssuedAt,
					expiryTime:      at.ExpiresAt,
					authorizedRoles: []string{"role"},
				},
				clientID: at.ClientID,
			}
			apm := &AccessProcessorMock{
				atc:     at,
				wantErr: nil,
			}
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, action, resource string) ([]string, error) {
					if domain != "domain" || len(roles) != 1 || roles[0] != "role" {
						return nil, errors.New("Audience/Scope mismatch")
					}
					return []string{"role"}, nil
				},
			}
			cert := &x509.Certificate{
				Issuer: pkix.Name{
					CommonName: "issuer cn",
				},
				Subject: pkix.Name{
					CommonName: "subject cn",
				},
			}
			return test{
				name: "test verify success with cert",
				args: args{
					ctx:  context.Background(),
					tok:  "dummyTok",
					act:  "dummyAct",
					res:  "dummyRes",
					cert: cert,
				},
				fields: fields{
					policyd:          pdm,
					accessProcessor:  apm,
					cache:            c,
					cacheExp:         time.Minute,
					cacheMemoryUsage: &atomic.Int64{},
				},
				wantErr:    "",
				wantResult: p,
				checkFunc: func(prov *authority) error {
					_, expiry, ok := prov.cache.GetWithExpire("dummyTok:issuer cn:subject cn:dummyAct:dummyRes")
					if !ok {
						return errors.New("cannot get issuer dummyTok:issuer cn:subject cn:dummyAct:dummyRes from cache")
					}
					wantExpiry := now.Add(time.Minute).UnixNano()
					if wantExpiry > expiry {
						return fmt.Errorf("cache expiry: got = %v, want: %v", expiry, wantExpiry)
					}
					return nil
				},
			}
		}(),
		func() test {
			now := fastime.Now()
			c := gache.New[Principal]()
			at := &access.OAuth2AccessTokenClaim{}
			p := &oAuthAccessToken{
				principal: principal{
					name:       at.BaseClaim.Subject,
					roles:      at.Scope,
					domain:     at.BaseClaim.Audience,
					issueTime:  at.IssuedAt,
					expiryTime: at.ExpiresAt,
				},
				clientID: at.ClientID,
			}
			c.SetWithExpire("dummyTok:dummyAct:dummyRes", p, time.Minute)
			apm := &AccessProcessorMock{
				atc:     at,
				wantErr: nil,
			}
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, action, resource string) ([]string, error) {
					if domain != "domain" || len(roles) != 1 || roles[0] != "role" {
						return nil, errors.New("Audience/Scope mismatch")
					}
					return []string{"role"}, nil
				},
			}
			return test{
				name: "test use cache success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:         pdm,
					accessProcessor: apm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr:    "",
				wantResult: p,
				checkFunc: func(prov *authority) error {
					_, expiry, ok := prov.cache.GetWithExpire("dummyTok:dummyAct:dummyRes")
					if !ok || prov.cache.Len() != 1 {
						return errors.New("cannot get dummyTok:dummyAct:dummyRes from cache")
					}
					wantExpiry := now.Add(time.Minute).UnixNano()
					if wantExpiry > expiry {
						return fmt.Errorf("cache expiry: got = %v, want: %v", expiry, wantExpiry)
					}
					return nil
				},
			}
		}(),
		func() test {
			now := fastime.Now()
			cert := &x509.Certificate{
				Issuer: pkix.Name{
					CommonName: "issuer cn",
				},
				Subject: pkix.Name{
					CommonName: "subject cn",
				},
			}
			c := gache.New[Principal]()
			at := &access.OAuth2AccessTokenClaim{}
			p := &oAuthAccessToken{
				principal: principal{
					name:       at.BaseClaim.Subject,
					roles:      at.Scope,
					domain:     at.BaseClaim.Audience,
					issueTime:  at.IssuedAt,
					expiryTime: at.ExpiresAt,
				},
				clientID: at.ClientID,
			}
			c.SetWithExpire("dummyTok:"+cert.Issuer.CommonName+":"+cert.Subject.CommonName+":dummyAct:dummyRes", p, time.Minute)
			apm := &AccessProcessorMock{
				atc:     at,
				wantErr: nil,
			}
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, action, resource string) ([]string, error) {
					if domain != "domain" || len(roles) != 1 || roles[0] != "role" {
						return nil, errors.New("Audience/Scope mismatch")
					}
					return []string{"role"}, nil
				},
			}
			return test{
				name: "test use cache success with cert",
				args: args{
					ctx:  context.Background(),
					tok:  "dummyTok",
					act:  "dummyAct",
					res:  "dummyRes",
					cert: cert,
				},
				fields: fields{
					policyd:         pdm,
					accessProcessor: apm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr:    "",
				wantResult: p,
				checkFunc: func(prov *authority) error {
					_, expiry, ok := prov.cache.GetWithExpire("dummyTok:issuer cn:subject cn:dummyAct:dummyRes")
					if !ok || prov.cache.Len() != 1 {
						return errors.New("cannot get issuer dummyTok:issuer cn:subject cn:dummyAct:dummyRes from cache")
					}
					wantExpiry := now.Add(time.Minute).UnixNano()
					if wantExpiry > expiry {
						return fmt.Errorf("cache expiry: got = %v, want: %v", expiry, wantExpiry)
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			c.Set("dummyTok:dummyAct:dummyRes", &principal{})
			apm := &AccessProcessorMock{
				atc:     &access.OAuth2AccessTokenClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty action",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "",
					res: "dummyRes",
				},
				fields: fields{
					policyd:         pdm,
					accessProcessor: apm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			c.Set("dummyTok:dummyAct:dummyRes", &principal{})
			apm := &AccessProcessorMock{
				atc:     &access.OAuth2AccessTokenClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty res",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "",
				},
				fields: fields{
					policyd:         pdm,
					accessProcessor: apm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			apm := &AccessProcessorMock{
				wantErr: errors.New("cannot parse access token"),
			}
			pdm := &PolicydMock{}
			return test{
				name: "test parse access token error",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:         pdm,
					accessProcessor: apm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "error authorize access token: cannot parse access token",
			}
		}(),
		func() test {
			c := gache.New[Principal]()
			apm := &AccessProcessorMock{
				atc: &access.OAuth2AccessTokenClaim{},
			}
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(context.Context, string, []string, string, string) ([]string, error) {
					return nil, errors.New("deny")
				},
			}
			return test{
				name: "test return deny",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:         pdm,
					accessProcessor: apm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "token unauthorized: deny",
			}
		}(),
		func() test {
			now := fastime.Now()
			cert := &x509.Certificate{
				Issuer: pkix.Name{
					CommonName: "issuer cn",
				},
				Subject: pkix.Name{
					CommonName: "subject cn",
				},
			}
			c := gache.New[Principal]()
			at := &access.OAuth2AccessTokenClaim{
				Scope: []string{"role"},
				BaseClaim: access.BaseClaim{
					StandardClaims: jwt.StandardClaims{
						Audience: "domain",
					},
				},
			}
			p := &oAuthAccessToken{
				principal: principal{
					name:            at.BaseClaim.Subject,
					roles:           at.Scope,
					domain:          at.BaseClaim.Audience,
					issueTime:       at.IssuedAt,
					expiryTime:      at.ExpiresAt,
					authorizedRoles: []string{"role"},
				},
				clientID: at.ClientID,
			}
			c.SetWithExpire("dummyTok:"+cert.Issuer.CommonName+":"+cert.Subject.CommonName+":dummyAct:dummyRes", p, time.Minute)
			apm := &AccessProcessorMock{
				atc:     at,
				wantErr: nil,
			}
			pdm := &PolicydMock{
				CheckPolicyRoleFunc: func(ctx context.Context, domain string, roles []string, action, resource string) ([]string, error) {
					if domain != "domain" || len(roles) != 1 || roles[0] != "role" {
						return nil, errors.New("Audience/Scope mismatch")
					}
					return []string{"role"}, nil
				},
			}
			return test{
				name: "test even if the cert is cached, it not used for access without cert, validate success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
					// no cert
				},
				fields: fields{
					policyd:          pdm,
					accessProcessor:  apm,
					cache:            c,
					cacheExp:         time.Minute,
					cacheMemoryUsage: &atomic.Int64{},
				},
				wantErr:    "",
				wantResult: p,
				checkFunc: func(prov *authority) error {
					_, expiry, ok := prov.cache.GetWithExpire("dummyTok:dummyAct:dummyRes")
					if !ok && prov.cache.Len() != 2 {
						return errors.New("cannot get dummyTok:dummyAct:dummyRes from cache")
					}
					wantExpiry := now.Add(time.Minute).UnixNano()
					if wantExpiry > expiry {
						return fmt.Errorf("cache expiry: got = %v, want: %v", expiry, wantExpiry)
					}
					return nil
				},
			}
		}(),
		func() test {
			cert := &x509.Certificate{
				Issuer: pkix.Name{
					CommonName: "issuer cn",
				},
				Subject: pkix.Name{
					CommonName: "subject cn",
				},
			}
			c := gache.New[Principal]()
			at := &access.OAuth2AccessTokenClaim{}
			p := &oAuthAccessToken{
				principal: principal{
					name:       at.BaseClaim.Subject,
					roles:      at.Scope,
					domain:     at.BaseClaim.Audience,
					issueTime:  at.IssuedAt,
					expiryTime: at.ExpiresAt,
				},
				clientID: at.ClientID,
			}
			c.SetWithExpire("dummyTok:"+cert.Issuer.CommonName+":"+cert.Subject.CommonName+":dummyAct:dummyRes", p, time.Minute)
			apm := &AccessProcessorMock{
				atc:     at,
				wantErr: errors.New("error mTLS client certificate is nil"),
			}
			pdm := &PolicydMock{}
			return test{
				name: "test even if the cert is cached, it not used for access without cert, validate fail",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
					// no cert
				},
				fields: fields{
					policyd:         pdm,
					accessProcessor: apm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "error authorize access token: error mTLS client certificate is nil",
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authority{
				policyd:          tt.fields.policyd,
				accessProcessor:  tt.fields.accessProcessor,
				cache:            tt.fields.cache,
				cacheExp:         tt.fields.cacheExp,
				cacheMemoryUsage: tt.fields.cacheMemoryUsage,
			}
			err := a.VerifyAccessToken(tt.args.ctx, tt.args.tok, tt.args.act, tt.args.res, tt.args.cert)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("authority.VerifyAccessToken() error want:%s, result: %s", tt.wantErr, err.Error())
					return
				}
			} else {
				if tt.wantErr != "" {
					t.Errorf("authority.VerifyAccessToken() return nil.  want %s", tt.wantErr)
					return
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(a); err != nil {
					t.Errorf("authority.VerifyAccessToken() error: %v", err)
				}
			}

			p, err := a.AuthorizeAccessToken(tt.args.ctx, tt.args.tok, tt.args.act, tt.args.res, tt.args.cert)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("authority.AuthorizeAccessToken() error want:%s, result: %s", tt.wantErr, err.Error())
					return
				}
			} else {
				if tt.wantErr != "" {
					t.Errorf("authority.AuthorizeAccessToken() return nil.  want %s", tt.wantErr)
					return
				}
				if !reflect.DeepEqual(p, tt.wantResult) {
					t.Errorf("authority.AuthorizeAccessToken() results don't match. want %#v, result %#v", tt.wantResult, p)
					return
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(a); err != nil {
					t.Errorf("authority.AuthorizeAccessToken() error: %v", err)
				}
			}
		})
	}
}
