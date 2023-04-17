// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
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
	testVulndb        = filepath.Join("testdata", "vulndb-v1")
	testVulndbFileURL = localURL(testVulndb)
	testIDs           = []string{
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
		if _, ok := c.(*client); !ok {
			t.Errorf("NewClient(%s) = %#v, want type *client", src, c)
		}
	})

	t.Run("http/v1", func(t *testing.T) {
		srv := newTestServer(testVulndb)
		t.Cleanup(srv.Close)

		c, err := NewClient(srv.URL, &Options{HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		cli, ok := c.(*client)
		if !ok {
			t.Errorf("NewClient(%s) = %#v, want type *client", srv.URL, c)
		}
		if _, ok := cli.source.(*httpSource); !ok {
			t.Errorf("NewClient(%s).source = %#v, want type *httpSource", srv.URL, cli.source)
		}
	})

	t.Run("http/legacy", func(t *testing.T) {
		srv := newTestServer(testLegacyVulndb)
		t.Cleanup(srv.Close)

		c, err := NewClient(srv.URL, &Options{HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := c.(*httpClient); !ok {
			t.Errorf("NewClient(%s) = %#v, want type *client", srv.URL, c)
		}
	})

	t.Run("local/v1", func(t *testing.T) {
		src := testVulndbFileURL
		c, err := NewClient(src, nil)
		if err != nil {
			t.Fatal(err)
		}
		cli, ok := c.(*client)
		if !ok {
			t.Errorf("NewClient(%s) = %#v, want type *client", src, c)
		}
		if _, ok := cli.source.(*localSource); !ok {
			t.Errorf("NewClient(%s).source = %#v, want type *localSource", src, cli.source)
		}
	})

	t.Run("local/legacy", func(t *testing.T) {
		src := testLegacyVulndbFileURL
		c, err := NewClient(src, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := c.(*localClient); !ok {
			t.Errorf("NewClient(%s) = %#v, want type *localClient", src, c)
		}
	})

}

func TestLastModifiedTime(t *testing.T) {
	test := func(t *testing.T, c Client) {
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

func TestByModule(t *testing.T) {
	tcs := []struct {
		module  string
		wantIDs []string
	}{
		{
			module:  "github.com/beego/beego",
			wantIDs: []string{"GO-2022-0463", "GO-2022-0569", "GO-2022-0572"},
		},
		{
			module:  "stdlib",
			wantIDs: []string{"GO-2021-0159", "GO-2021-0240", "GO-2021-0264", "GO-2022-0229", "GO-2022-0273"},
		},
		{
			module:  "toolchain",
			wantIDs: []string{"GO-2021-0068", "GO-2022-0475", "GO-2022-0476"},
		},
		{
			module:  "golang.org/x/crypto",
			wantIDs: []string{"GO-2022-0229"},
		},
		{
			module:  "does.not/exist",
			wantIDs: nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.module, func(t *testing.T) {
			test := func(t *testing.T, c Client) {
				got, err := c.ByModule(context.Background(), tc.module)
				if err != nil {
					t.Fatal(err)
				}
				want, err := entries(tc.wantIDs)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(got, want); diff != "" {
					t.Errorf("ByModule: unexpected diff (-got,+want):\n%s", diff)
				}
			}
			testAllClientTypes(t, test)
		})
	}
}

// testAllClientTypes runs a given test for all client types.
func testAllClientTypes(t *testing.T, test func(t *testing.T, c Client)) {
	t.Run("http", func(t *testing.T) {
		srv := newTestServer(testVulndb)
		t.Cleanup(srv.Close)

		hc, err := NewV1Client(srv.URL, &Options{HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}

		test(t, hc)
	})

	t.Run("local", func(t *testing.T) {
		fc, err := NewV1Client(testVulndbFileURL, nil)
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
