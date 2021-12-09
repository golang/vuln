// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package worker

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/vuln/internal/cveschema"
)

var usePkgsite = flag.Bool("pkgsite", false, "use pkg.go.dev for tests")

func TestTriageV4CVE(t *testing.T) {
	ctx := context.Background()
	url := getPkgsiteURL(t)

	for _, test := range []struct {
		name string
		in   *cveschema.CVE
		want string
	}{
		{
			"repo path is Go standard library",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://pkg.go.dev/net/http"},
						{URL: "https://groups.google.com/forum/#!topic/golang-nuts/1234"},
					},
				},
			},
			stdlibPath,
		},
		{
			"repo path is is valid golang.org module path",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://groups.google.com/forum/#!topic/golang-nuts/1234"},
						{URL: "https://golang.org/x/mod"},
					},
				},
			},
			"golang.org/x/mod",
		},
		{
			"contains github.com but not on pkg.go.dev",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://github.com/something/something/404"},
					},
				},
			},
			"",
		},
		{
			"contains longer module path",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://bitbucket.org/foo/bar/baz/v2"},
					},
				},
			},
			"bitbucket.org/foo/bar/baz/v2",
		},
		{
			"repo path is not a module",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://bitbucket.org/foo/bar"},
					},
				},
			},
			"",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.in.DataVersion = "4.0"
			got, err := TriageCVE(ctx, test.in, url)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				if test.want != "" {
					t.Fatalf("got empty string, want %q", test.want)
				}
				return
			}
			if got.modulePath != test.want {
				t.Errorf("got %q, want %q", got.modulePath, test.want)
			}
		})
	}
}

func TestKnownToPkgsite(t *testing.T) {
	ctx := context.Background()

	const validModule = "golang.org/x/mod"
	url := getPkgsiteURL(t)

	for _, test := range []struct {
		in   string
		want bool
	}{
		{validModule, true},
		{"github.com/something/something", false},
	} {
		t.Run(test.in, func(t *testing.T) {
			got, err := knownToPkgsite(ctx, url, test.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("%s: got %t, want %t", test.in, got, test.want)
			}
		})
	}
}

// getPkgsiteURL returns a URL to either a fake server or the real pkg.go.dev,
// depending on the usePkgsite flag.
func getPkgsiteURL(t *testing.T) string {
	if *usePkgsite {
		return pkgsiteURL
	}
	// Start a test server that recognizes anything from golang.org and bitbucket.org/foo/bar/baz.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modulePath := strings.TrimPrefix(r.URL.Path, "/mod/")
		if !strings.HasPrefix(modulePath, "golang.org/") &&
			!strings.HasPrefix(modulePath, "bitbucket.org/foo/bar/baz") {
			http.Error(w, "unknown", http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s.URL
}
