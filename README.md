# Athenz authorizer

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/AthenZ/athenz-authorizer?style=flat-square&label=Github%20version)](https://github.com/AthenZ/athenz-authorizer/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/AthenZ/athenz-authorizer)](https://goreportcard.com/report/github.com/AthenZ/athenz-authorizer)
[![GoDoc](http://godoc.org/github.com/AthenZ/athenz-authorizer?status.svg)](http://godoc.org/github.com/AthenZ/athenz-authorizer)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](code_of_conduct.md)

<!-- TOC insertAnchor:false -->

- [Athenz authorizer](#athenz-authorizer)
  - [What is Athenz authorizer](#what-is-athenz-authorizer)
  - [Usage](#usage)
  - [How it works](#how-it-works)
    - [Athenz public key daemon](#athenz-public-key-daemon)
    - [Athenz policy daemon](#athenz-policy-daemon)
  - [Configuration](#configuration)
    - [AccessTokenParam](#accesstokenparam)
  - [About releases](#about-releases)
  - [Authors](#authors)

<!-- /TOC -->

## What is Athenz authorizer

Athenz authorizer is a library to cache the policies of [Athenz](https://github.com/AthenZ/athenz) to authorizer authentication and authorization check of user request.

![Overview](./docs/assets/policy_updater_overview.png)

## Usage

To initialize authorizer.

```golang
package main

import (
    "context"
    "crypto/x509"
    "encoding/pem"
    "log"

    authorizerd "github.com/AthenZ/athenz-authorizer/v5"
)

func main() {
    // Initialize authorizerd
    daemon, err := authorizerd.New(
        authorizerd.WithAthenzURL("www.athenz.io"), // set athenz URL
        authorizerd.WithAthenzDomains("domain1", "domain2", "domain N"), // set athenz domains
        authorizerd.WithPubkeyRefreshPeriod("12h"), // optional, default: 24h
        authorizerd.WithPolicyRefreshPeriod("1h"), // optional, default: 30m
    )
    if err != nil {
        // cannot initialize authorizer daemon
        log.Fatalf("daemon new error: %v", err)
    }

    // Start authorizer daemon
    ctx := context.Background() // user can control authorizer daemon lifetime using this context
    if err = daemon.Init(ctx); err != nil { // initialize internal daemons in dependency order (e.g. public keys before signed policies)
        // cannot initialize internal daemons inside authorizer
        log.Fatalf("daemon init error: %v", err)
    }
    errs := daemon.Start(ctx)
    go func() {
        for err := range errs {
            // user should handle errors return from the daemon
            log.Printf("daemon start error: %v", err)
        }
    }()

    act := "action"
    res := "resource"

    // Authorize with access token
    at := "<certificate bound access token>"
    certPEM := "<binding certificate>"
    block, _ := pem.Decode([]byte(certPEM))
    if block == nil {
        log.Fatalln("failed to parse certificate PEM")
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Fatalf("invalid x509 certificate: %v", err)
    }
    atp, err := daemon.AuthorizeAccessToken(ctx, at, act, res, cert)
    if err != nil {
        // NOT authorized, please take appropriate action
        log.Fatalf("access token not authorized: %v", err)
    }
    log.Printf("authorized principal in access token: %#v", atp)

    // Authorize with role token
    rt := "<role token>"
    rtp, err := daemon.AuthorizeRoleToken(ctx, rt, act, res)
    if err != nil {
        // NOT authorized, please take appropriate action
        log.Fatalf("role token not authorized: %v", err)
    }
    log.Printf("authorized principal in role token: %#v", rtp)
}
```

## How it works

To do the authentication and authorization check, the user needs to specify which [domain data](https://github.com/AthenZ/athenz/blob/master/docs/data_model.md#data-model) to be cache. The authorizer will periodically refresh the policies and Athenz public key data to [verify and decode](https://github.com/AthenZ/athenz/blob/master/docs/zpu_policy_file.md#zts-signature-validation) the domain data. The verified domain data will cache into the memory, and use for authentication and authorization check.

The authorizer contains two sub-module, Athenz public key daemon (pubkeyd) and Athenz policy daemon (policyd).

### Athenz public key daemon

Athenz public key daemon (pubkeyd) is responsible for periodically update the Athenz public key data from Athenz server to verify the policy data received from Athenz policy daemon and verify the role token.

### Athenz policy daemon

Athenz policy daemon (policyd) is responsible for periodically update the policy data of specified Athenz domain from Athenz server. The received policy data will be verified using the public key got from pubkeyd, and cache into memory. Whenever user requesting for the access check, the verification check will be used instead of asking Athenz server every time.

## Configuration

The authorizer uses functional options pattern to initialize the instance. All the options are defined [here](./option.go).

| Option name             | Description                                                                   | Default Value                                 | Required | Example                                      |
| ----------------------- | ----------------------------------------------------------------------------- | --------------------------------------------- | -------- | -------------------------------------------- |
| AthenzURL               | The Athenz server URL                                                         | athenz\.io/zts/v1                             | Yes      | "athenz\.io/zts/v1"                          |
| AthenzDomains           | Athenz domain names that contain the RBAC policies                            | \[\]                                          | Yes      | "domName1", "domName2"                       |
| HTTPClient              | The HTTP client for connecting to Athenz server                               | http\.Client\{ Timeout: 30 \* time\.Second \} | No       | http\.DefaultClient                          |
| CacheExp                | The TTL of the success cache                                                  | 1 Minute                                      | No       | 1 \* time\.Minute                            |
| Enable/DisablePubkeyd   | Run public key daemon or not                                                  | true                                          | No       |                                              |
| PubkeySysAuthDomain     | System authority domain name to retrieve Athenz public key data               | sys\.auth                                     | No       | "sys.auth"                                   |
| PubkeyRefreshPeriod     | Period to refresh the Athenz public key data                                  | 24 Hours                                      | No       | "24h"                                        |
| PubkeyETagExpiry        | ETag cache TTL of Athenz public key data                                      | 168 Hours \(1 Week\)                          | No       | "168h"                                       |
| PubkeyETagPurgePeriod   | ETag cache purge duration                                                     | 84 Hours                                      | No       | "84h"                                        |
| PubkeyRetryDelay        | Delay of next retry on request failed                                         | 1 Minute                                      | No       | "1m"                                         |
| Enable/DisablePolicyd   | Run policy daemon or not                                                      | true                                          | No       |                                              |
| PolicyExpiryMargin      | Update the policy by a margin duration before the policy actually expires     | 3 Hours                                       | No       | "3h"                                         |
| PolicyRefreshPeriod     | Period to refresh the Athenz policies                                         | 30 Minutes                                    | No       | "30m"                                        |
| PolicyPurgePeriod       | Policy cache purge duration                                                   | 1 Hours                                       | No       | "1h"                                         |
| PolicyRetryDelay        | Delay of next retry on request fail                                           | 1 Minute                                      | No       | "1m"                                         |
| PolicyRetryAttempts     | Maximum retry attempts on request fail                                        | 2                                             | No       | 2                                            |
| Enable/DisableJwkd      | Run JWK daemon or not                                                         | true                                          | No       |                                              |
| JwkRefreshPeriod        | Period to refresh the Athenz JWK                                              | 24 Hours                                      | No       | "24h"                                        |
| JwkRetryDelay           | Delay of next retry on request fail                                           | 1 Minute                                      | No       | "1m"                                         |
| jwkURLs                 | URL to get jwk other than  AthenzURL                                          | []                                            | No       | "http://domain1/jwks", "http://domain2/jwks" |
| AccessTokenParam        | Use access token verification, details: [AccessTokenParam](#accesstokenparam) | Same as [AccessTokenParam](#accesstokenparam) | No       | \{\}                                         |
| Enable/DisableRoleToken | Use role token verification or not                                            | true                                          | No       |                                              |
| RoleAuthHeader          | The HTTP header to extract role token                                         | Athenz\-Role\-Auth                            | No       | "Athenz\-Role\-Auth"                         |
| Enable/DisableRoleCert  | Use role certificate verification or not                                      | true                                          | No       |                                              |
| RoleCertURIPrefix       | Extract role from role certificate                                            | athenz://role/                                | No       | "athenz://role/"                             |
| OutputAuthorizedPrincipalLog | Output the name of the authenticated Principal to the log | false | No | |

### AccessTokenParam

| **Option name**      | **Description**                                                                | **Default Value** | **Required** | **Example**                                    |
| -------------------- | ------------------------------------------------------------------------------ | ----------------- | ------------ | ---------------------------------------------- |
| enable               | Use access token verification or not                                           | true              | No           | true                                           |
| verifyCertThumbprint | Use certificate bound access token verification                                | true              | No           | true                                           |
| certBackdateDur      | Backdate duration of the issue time of the certificate                         | 1 Hour            | No           | "1h"                                           |
| certOffsetDur        | Offset window to accept access token with a mismatching certificate thumbprint | 1 Hour            | No           | "1h"                                           |
| verifyClientID       | Use authorized client ID verification                                          | false             | No           | false                                          |
| authorizedClientIDs  | Authorized client ID to certificate common name map                            | nil               | No           | \{ "atClientID": \{ "certCN1", "certCN2" \} \} |

## About releases

- Releases
  - [![GitHub release (latest by date)](https://img.shields.io/github/v/release/AthenZ/athenz-authorizer?style=flat-square&label=Github%20version)](https://github.com/AthenZ/athenz-authorizer/releases/latest)

## Authors

- [kpango](https://github.com/kpango)
- [kevindiu](https://github.com/kevindiu)
- [TakuyaMatsu](https://github.com/TakuyaMatsu)
- [tatyano](https://github.com/tatyano)
- [WindzCUHK](https://github.com/WindzCUHK)
