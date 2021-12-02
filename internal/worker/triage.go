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
	"strings"
	"time"

	"golang.org/x/exp/event"
	"golang.org/x/time/rate"
	"golang.org/x/vuln/internal/cveschema"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/worker/log"
)

var errCVEVersionUnsupported = errors.New("unsupported CVE version")

var vcsHostsWithThreeElementRepoName = map[string]bool{
	"bitbucket.org": true,
	"gitea.com":     true,
	"gitee.com":     true,
	"github.com":    true,
	"gitlab.com":    true,
	"golang.org":    true,
}

var stdlibKeywords = map[string]bool{
	"github.com/golang": true,
	"golang-announce":   true,
	"golang-nuts":       true,
	"golang.org":        true,
}

// TriageCVE reports whether the CVE refers to a Go module.
func TriageCVE(ctx context.Context, c *cveschema.CVE, pkgsiteURL string) (_ bool, err error) {
	defer derrors.Wrap(&err, "triageCVE(%q)", c.ID)
	switch c.DataVersion {
	case "4.0":
		mp, err := cveModulePath(ctx, c, pkgsiteURL)
		if err != nil {
			return false, err
		}
		if mp == "" {
			return false, nil
		}
		return true, nil
	default:
		// TODO(https://golang.org/issue/49289): Add support for v5.0.
		return false, fmt.Errorf("CVE %q has DataVersion %q: %w", c.ID, c.DataVersion, errCVEVersionUnsupported)
	}
}

// cveModulePath returns a Go module path for a CVE, if we can determine what
// it is.
// TODO(golang/go#49733) Use the CandidateModulePaths function from pkgsite to catch
// longer module paths, e.g. github.com/pulumi/pulumi/sdk/v2.
func cveModulePath(ctx context.Context, c *cveschema.CVE, pkgsiteURL string) (_ string, err error) {
	defer derrors.Wrap(&err, "cveModulePath(%q)", c.ID)
	for _, r := range c.References.Data {
		if r.URL == "" {
			continue
		}
		for k := range stdlibKeywords {
			if strings.Contains(r.URL, k) {
				return "Go Standard Library", nil
			}
		}
		for host := range vcsHostsWithThreeElementRepoName {
			if !strings.Contains(r.URL, host) {
				continue
			}
			refURL, err := url.Parse(r.URL)
			if err != nil {
				return "", fmt.Errorf("url.Parse(%q): %v", r.URL, err)
			}
			u := refURL.Host + refURL.Path
			parts := strings.Split(u, "/")
			if len(parts) < 3 {
				continue
			}
			mod := strings.Join(parts[0:3], "/")
			known, err := knownToPkgsite(ctx, pkgsiteURL, mod)
			if err != nil {
				return "", err
			}
			if known {
				return mod, nil
			}
		}
	}
	return "", nil
}

// Limit pkgsite calls to 2 qps (once every 500ms).
// The second argument to rate.NewLimiter is the burst, which
// basically lets you exceed the rate briefly.
var pkgsiteRateLimiter = rate.NewLimiter(rate.Every(500*time.Millisecond), 3)

var seenModulePath = map[string]bool{}

// knownToPkgsite reports whether pkgsite knows that modulePath actually refers
// to a module.
func knownToPkgsite(ctx context.Context, url, modulePath string) (bool, error) {
	// If we've seen it before, no need to call.
	if b, ok := seenModulePath[modulePath]; ok {
		return b, nil
	}
	// Pause to maintain a max QPS.
	if err := pkgsiteRateLimiter.Wait(ctx); err != nil {
		return false, err
	}
	msg := fmt.Sprintf("call to %s", url)
	log.Info(ctx, msg+" starting", event.String("path", modulePath))
	start := time.Now()
	res, err := http.Get(url + "/mod/" + modulePath)
	log.Info(ctx, msg+" ended",
		event.String("path", modulePath),
		event.Value("latency", time.Since(start)),
		event.Value("error", err))
	if err != nil {
		return false, err
	}
	known := res.StatusCode == http.StatusOK
	seenModulePath[modulePath] = known
	return known, nil
}
