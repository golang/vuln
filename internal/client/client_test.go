// Copyright 2021 The Go Authors. All rights reserved.
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
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/vuln/internal/web"
)

func newTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("testdata/vulndb")))
	return httptest.NewServer(mux)
}

var localURL = func() string {
	absDir, err := filepath.Abs("testdata/vulndb")
	if err != nil {
		panic(fmt.Sprintf("failed to read testdata/vulndb: %v", err))
	}
	u, err := web.URLFromFilePath(absDir)
	if err != nil {
		panic(fmt.Sprintf("failed to read testdata/vulndb: %v", err))
	}
	return u.String()
}()

func TestByModule(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}
	ctx := context.Background()
	// Create a local http database.
	srv := newTestServer()
	defer srv.Close()

	const (
		modulePath  = "github.com/BeeGo/beego"
		detailStart = "Routes in the beego HTTP router"

		modulePathLowercase  = "github.com/tidwall/gjson"
		detailStartLowercase = "Due to improper bounds checking"
	)
	for _, test := range []struct {
		name         string
		source       string
		module       string
		detailPrefix string
		wantVulns    int
	}{
		{name: "http", source: srv.URL, module: modulePath, detailPrefix: detailStart, wantVulns: 3},
		{name: "file", source: localURL, module: modulePath, detailPrefix: detailStart, wantVulns: 3},
		{name: "lower-http", source: srv.URL, module: modulePathLowercase, detailPrefix: detailStartLowercase, wantVulns: 4},
		{name: "lower-file", source: localURL, module: modulePathLowercase, detailPrefix: detailStartLowercase, wantVulns: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(test.source, Options{})
			if err != nil {
				t.Fatal(err)
			}

			// First call fills cache, if present.
			if _, err := client.ByModule(ctx, test.module); err != nil {
				t.Fatal(err)
			}
			vulns, err := client.ByModule(ctx, test.module)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := len(vulns), test.wantVulns; got != want {
				t.Fatalf("got %d vulns for %s, want %d", got, test.module, want)
			}

			if v := vulns[0]; !strings.HasPrefix(v.Details, test.detailPrefix) {
				got := v.Details
				if len(got) > len(test.detailPrefix) {
					got = got[:len(test.detailPrefix)] + "..."
				}
				t.Errorf("got\n\t%s\nbut should start with\n\t%s", got, test.detailPrefix)
			}
		})
	}
}

// TestMustUseIndex checks that httpSource in NewClient(...)
//   - always calls Index function before making an http
//     request in ByModule.
//   - if an http request was made, then the module path
//     must be in the index.
//
// This test serves as an approximate mechanism to make sure
// that we only send module info to the vuln db server if the
// module has known vulnerabilities. Otherwise, we might send
// unknown private module information to the db.
func TestMustUseIndex(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}
	ctx := context.Background()
	// Create a local http database.
	srv := newTestServer()
	defer srv.Close()

	// List of modules to query, some are repeated to exercise cache hits.
	modulePaths := []string{"github.com/BeeGo/beego", "github.com/tidwall/gjson", "net/http", "abc.xyz", "github.com/BeeGo/beego"}
	clt, err := NewClient(srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	hs := clt.(*httpSource)
	for _, modulePath := range modulePaths {
		indexCalls := hs.indexCalls
		httpCalls := hs.httpCalls
		if _, err := clt.ByModule(ctx, modulePath); err != nil {
			t.Fatal(err)
		}
		// Number of index Calls should be increased.
		if hs.indexCalls == indexCalls {
			t.Errorf("ByModule(ctx, %s) did not call Index(...)", modulePath)
		}
		// If http request was made, then the modulePath must be in the index.
		if hs.httpCalls > httpCalls {
			index, err := hs.Index(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, present := index[modulePath]
			if !present {
				t.Errorf("ByModule(ctx, %s) issued http request for module not in Index(...)", modulePath)
			}
		}
	}
}

func TestSpecialPaths(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}
	ctx := context.Background()
	srv := newTestServer()
	defer srv.Close()

	for _, test := range []struct {
		name   string
		source string
	}{
		{"local", localURL},
		{"http", srv.URL},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(test.source, Options{})
			if err != nil {
				t.Fatal(err)
			}
			for specialPath := range specialCaseModulePaths {
				t.Run(test.name+"-"+specialPath, func(t *testing.T) {
					if _, err := client.ByModule(ctx, specialPath); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestCorrectFetchesNoCache(t *testing.T) {
	fetches := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches[r.URL.Path]++
		if r.URL.Path == "/index.json" {
			j, _ := json.Marshal(DBIndex{
				"m.com/a": time.Now(),
				"m.com/b": time.Now(),
			})
			w.Write(j)
		} else {
			w.Write([]byte("[]"))
		}
	}))
	defer ts.Close()

	hs := &httpSource{url: ts.URL, c: new(http.Client)}
	for _, module := range []string{"m.com/a", "m.com/b", "m.com/c"} {
		if _, err := hs.ByModule(context.Background(), module); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
	expectedFetches := map[string]int{"/index.json": 3,
		"/m.com/a.json": 1, "/m.com/b.json": 1}
	if !reflect.DeepEqual(fetches, expectedFetches) {
		t.Errorf("unexpected fetches, got %v, want %v", fetches, expectedFetches)
	}
}

func TestLastModifiedTime(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}

	srv := newTestServer()
	defer srv.Close()

	info, err := os.Stat(filepath.Join("testdata", "vulndb", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := info.ModTime().Truncate(time.Second).In(time.UTC)
	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "http", source: srv.URL},
		{name: "file", source: localURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(test.source, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.LastModifiedTime(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			got = got.Truncate(time.Second)
			if !got.Equal(want) {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}
