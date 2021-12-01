// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/vuln/internal/worker/log"
)

func TestKnownToPkgsite(t *testing.T) {
	ctx := log.WithLineLogger(context.Background())

	const validModule = "golang.org/x/mod"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modulePath := strings.TrimPrefix(r.URL.Path, "/mod/")
		if modulePath != validModule {
			http.Error(w, "unknown", http.StatusNotFound)
		}
	}))
	defer s.Close()

	for _, test := range []struct {
		in   string
		want bool
	}{
		{validModule, true},
		{"github.com/something/something", false},
	} {
		t.Run(test.in, func(t *testing.T) {
			got, err := knownToPkgsite(ctx, s.URL, test.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("got %t, want %t", got, test.want)
			}
		})
	}
}
