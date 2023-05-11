// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/web"
)

var (
	testLegacyVulndb        = filepath.Join("testdata", "vulndb-legacy")
	testLegacyVulndbFileURL = localURL(testLegacyVulndb)
	testVulndb              = filepath.Join("testdata", "vulndb-v1")
	testVulndbFileURL       = localURL(testVulndb)
	testFlatVulndb          = filepath.Join("testdata", "vulndb-v1", "ID")
	testFlatVulndbFileURL   = localURL(testFlatVulndb)
	testIDs                 = []string{
		"GO-2021-0159",
		"GO-2022-0229",
		"GO-2022-0463",
		"GO-2022-0569",
		"GO-2022-0572",
		"GO-2021-0068",
		"GO-2022-0475",
		"GO-2022-0476",
		"GO-2021-0240",
		"GO-2021-0264",
		"GO-2022-0273",
	}
)

func newTestServer(dir string) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(dir)))
	return httptest.NewServer(mux)
}

func entries(ids []string) ([]*osv.Entry, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	entries := make([]*osv.Entry, len(ids))
	for i, id := range ids {
		b, err := os.ReadFile(filepath.Join(testVulndb, idDir, id+".json"))
		if err != nil {
			return nil, err
		}
		var entry osv.Entry
		if err := json.Unmarshal(b, &entry); err != nil {
			return nil, err
		}
		entries[i] = &entry
	}
	return entries, nil
}

func localURL(dir string) string {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		panic(fmt.Sprintf("failed to read %s: %v", dir, err))
	}
	u, err := web.URLFromFilePath(absDir)
	if err != nil {
		panic(fmt.Sprintf("failed to read %s: %v", dir, err))
	}
	return u.String()
}

func TestNewClient(t *testing.T) {
	t.Run("vuln.go.dev", func(t *testing.T) {
		src := "https://vuln.go.dev"
		c, err := NewClient(src, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			t.Errorf("NewClient(%s) = nil, want instantiated *Client", src)
		}
	})

	t.Run("http/v1", func(t *testing.T) {
		srv := newTestServer(testVulndb)
		t.Cleanup(srv.Close)

		c, err := NewClient(srv.URL, &Options{HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			t.Errorf("NewClient(%s) = nil, want instantiated *Client", srv.URL)
		}
	})

	t.Run("http/legacy", func(t *testing.T) {
		srv := newTestServer(testLegacyVulndb)
		t.Cleanup(srv.Close)

		_, err := NewClient(srv.URL, &Options{HTTPClient: srv.Client()})
		if err == nil || !errors.Is(err, errUnknownSchema) {
			t.Errorf("NewClient() = %s, want error %s", err, errUnknownSchema)
		}
	})

	t.Run("local/v1", func(t *testing.T) {
		src := testVulndbFileURL
		c, err := NewClient(src, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			t.Errorf("NewClient(%s) = nil, want instantiated *Client", src)
		}
	})

	t.Run("local/flat", func(t *testing.T) {
		src := testFlatVulndbFileURL
		c, err := NewClient(src, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			t.Errorf("NewClient(%s) = nil, want instantiated *Client", src)
		}
	})

	t.Run("local/legacy", func(t *testing.T) {
		src := testLegacyVulndbFileURL
		_, err := NewClient(src, nil)
		if err == nil || !errors.Is(err, errUnknownSchema) {
			t.Errorf("NewClient() = %s, want error %s", err, errUnknownSchema)
		}
	})
}

func TestLastModifiedTime(t *testing.T) {
	test := func(t *testing.T, c *Client) {
		got, err := c.LastModifiedTime(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		want, err := time.Parse(time.RFC3339, "2023-04-03T15:57:51Z")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("LastModifiedTime = %s, want %s", got, want)
		}
	}
	testAllClientTypes(t, test)
}

func TestByModules(t *testing.T) {
	tcs := []struct {
		module  *ModuleRequest
		wantIDs []string
	}{
		{
			module: &ModuleRequest{
				Path: "github.com/beego/beego",
			},
			wantIDs: []string{"GO-2022-0463", "GO-2022-0569", "GO-2022-0572"},
		},
		{
			module: &ModuleRequest{
				Path: "github.com/beego/beego",
				// "GO-2022-0463" not affected at this version.
				Version: "1.12.10",
			},
			wantIDs: []string{"GO-2022-0569", "GO-2022-0572"},
		},
		{
			module: &ModuleRequest{
				Path: "stdlib",
			},
			wantIDs: []string{"GO-2021-0159", "GO-2021-0240", "GO-2021-0264", "GO-2022-0229", "GO-2022-0273"},
		},
		{
			module: &ModuleRequest{
				Path:    "stdlib",
				Version: "go1.17",
			},
			wantIDs: []string{"GO-2021-0264", "GO-2022-0273"},
		},
		{
			module: &ModuleRequest{
				Path: "toolchain",
			},
			wantIDs: []string{"GO-2021-0068", "GO-2022-0475", "GO-2022-0476"},
		},
		{
			module: &ModuleRequest{
				Path: "toolchain",
				// All vulns affected at this version.
				Version: "1.14.13",
			},
			wantIDs: []string{"GO-2021-0068", "GO-2022-0475", "GO-2022-0476"},
		},
		{
			module: &ModuleRequest{
				Path: "golang.org/x/crypto",
			},
			wantIDs: []string{"GO-2022-0229"},
		},
		{
			module: &ModuleRequest{
				Path: "golang.org/x/crypto",
				// Vuln was fixed at exactly this version.
				Version: "1.13.7",
			},
			wantIDs: nil,
		},
		{
			module: &ModuleRequest{
				Path: "does.not/exist",
			},
			wantIDs: nil,
		},
		{
			module: &ModuleRequest{
				Path:    "does.not/exist",
				Version: "1.0.0",
			},
			wantIDs: nil,
		},
	}

	// Test each case as an individual call to ByModules.
	for _, tc := range tcs {
		t.Run(tc.module.Path+"@"+tc.module.Version, func(t *testing.T) {
			test := func(t *testing.T, c *Client) {
				got, err := c.ByModules(context.Background(), []*ModuleRequest{tc.module})
				if err != nil {
					t.Fatal(err)
				}
				wantEntries, err := entries(tc.wantIDs)
				if err != nil {
					t.Fatal(err)
				}
				want := []*ModuleResponse{{
					Path:    tc.module.Path,
					Version: tc.module.Version,
					Entries: wantEntries,
				}}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("ByModule() mismatch (-want +got):\n%s", diff)
				}
			}
			testAllClientTypes(t, test)
		})
	}

	// Now create a single test that makes all the requests
	// in a single call to ByModules.
	reqs := make([]*ModuleRequest, len(tcs))
	want := make([]*ModuleResponse, len(tcs))
	for i, tc := range tcs {
		reqs[i] = tc.module
		wantEntries, err := entries(tc.wantIDs)
		if err != nil {
			t.Fatal(err)
		}
		want[i] = &ModuleResponse{
			Path:    tc.module.Path,
			Version: tc.module.Version,
			Entries: wantEntries,
		}
	}

	t.Run("all", func(t *testing.T) {
		test := func(t *testing.T, c *Client) {
			got, err := c.ByModules(context.Background(), reqs)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("ByModules() mismatch (-want +got):\n%s", diff)
			}
		}
		testAllClientTypes(t, test)
	})
}

// testAllClientTypes runs a given test for all client types.
func testAllClientTypes(t *testing.T, test func(t *testing.T, c *Client)) {
	t.Run("http", func(t *testing.T) {
		srv := newTestServer(testVulndb)
		t.Cleanup(srv.Close)

		hc, err := NewClient(srv.URL, &Options{HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}

		test(t, hc)
	})

	t.Run("local", func(t *testing.T) {
		fc, err := NewClient(testVulndbFileURL, nil)
		if err != nil {
			t.Fatal(err)
		}

		test(t, fc)
	})

	t.Run("hybrid", func(t *testing.T) {
		fc, err := NewClient(testFlatVulndbFileURL, nil)
		if err != nil {
			t.Fatal(err)
		}

		test(t, fc)
	})

	t.Run("in-memory", func(t *testing.T) {
		testEntries, err := entries(testIDs)
		if err != nil {
			t.Fatal(err)
		}
		mc, err := NewInMemoryClient(testEntries)
		if err != nil {
			t.Fatal(err)
		}

		test(t, mc)
	})
}
