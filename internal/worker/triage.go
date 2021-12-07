// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/event"
	"golang.org/x/time/rate"
	"golang.org/x/vuln/internal/cveschema"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/worker/log"
)

var errCVEVersionUnsupported = errors.New("unsupported CVE version")

var stdlibKeywords = map[string]bool{
	"github.com/golang": true,
	"golang-announce":   true,
	"golang-nuts":       true,
	"golang.org":        true,
}

// TriageCVE reports whether the CVE refers to a Go module.
func TriageCVE(ctx context.Context, c *cveschema.CVE, pkgsiteURL string) (_ *triageResult, err error) {
	defer derrors.Wrap(&err, "triageCVE(%q)", c.ID)
	switch c.DataVersion {
	case "4.0":
		return triageV4CVE(ctx, c, pkgsiteURL)
	default:
		// TODO(https://golang.org/issue/49289): Add support for v5.0.
		return nil, fmt.Errorf("CVE %q has DataVersion %q: %w", c.ID, c.DataVersion, errCVEVersionUnsupported)
	}
}

type triageResult struct {
	modulePath string
	stdlib     bool
	reason     string
}

// triageV4CVE triages a CVE following schema v4.0 and returns the result.
func triageV4CVE(ctx context.Context, c *cveschema.CVE, pkgsiteURL string) (_ *triageResult, err error) {
	defer derrors.Wrap(&err, "triageV4CVE(ctx, %q, %q)", c.ID, pkgsiteURL)
	for _, r := range c.References.Data {
		if r.URL == "" {
			continue
		}
		for k := range stdlibKeywords {
			if strings.Contains(r.URL, k) && !strings.Contains(r.URL, "golang.org/x/") {
				return &triageResult{
					modulePath: "Go Standard Library",
					stdlib:     true,
					reason:     fmt.Sprintf("Reference data URL %q contains %q", r.URL, k),
				}, nil
			}
		}
		refURL, err := url.Parse(r.URL)
		if err != nil {
			return nil, fmt.Errorf("url.Parse(%q): %v", r.URL, err)
		}
		modpaths := candidateModulePaths(refURL.Host + refURL.Path)
		for _, mp := range modpaths {
			known, err := knownToPkgsite(ctx, pkgsiteURL, mp)
			if err != nil {
				return nil, err
			}
			if known {
				u := pkgsiteURL + "/" + mp
				return &triageResult{
					modulePath: mp,
					reason:     fmt.Sprintf("Reference data URL %q contains path %q; %q returned a status 200", r.URL, mp, u),
				}, nil
			}
		}
	}
	return nil, nil
}

// Limit pkgsite calls to 2 qps (once every 500ms).
// The second argument to rate.NewLimiter is the burst, which
// basically lets you exceed the rate briefly.
var pkgsiteRateLimiter = rate.NewLimiter(rate.Every(500*time.Millisecond), 3)

var seenModulePath = map[string]bool{}

// knownToPkgsite reports whether pkgsite knows that modulePath actually refers
// to a module.
func knownToPkgsite(ctx context.Context, baseURL, modulePath string) (bool, error) {
	// If we've seen it before, no need to call.
	if b, ok := seenModulePath[modulePath]; ok {
		return b, nil
	}
	// Pause to maintain a max QPS.
	if err := pkgsiteRateLimiter.Wait(ctx); err != nil {
		return false, err
	}
	start := time.Now()

	url := baseURL + "/mod/" + modulePath
	res, err := http.Head(url)
	var status string
	if err == nil {
		status = strconv.Quote(res.Status)
	}
	log.Info(ctx, "HEAD "+url,
		event.Value("latency", time.Since(start)),
		event.String("status", status),
		event.Value("error", err))
	if err != nil {
		return false, err
	}
	known := res.StatusCode == http.StatusOK
	seenModulePath[modulePath] = known
	return known, nil
}
