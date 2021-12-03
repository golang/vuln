// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/vuln/internal/worker/log"
)

var usePkgsite = flag.Bool("pkgsite", false, "use pkg.go.dev for tests")

func TestKnownToPkgsite(t *testing.T) {
	ctx := log.WithLineLogger(context.Background())

	const validModule = "golang.org/x/mod"

	var url string

	if *usePkgsite {
		url = "https://pkg.go.dev"
	} else {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			modulePath := strings.TrimPrefix(r.URL.Path, "/mod/")
			if modulePath != validModule {
				http.Error(w, "unknown", http.StatusNotFound)
			}
		}))
		defer s.Close()
		url = s.URL
	}

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
