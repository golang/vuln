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
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/web"
	"golang.org/x/vuln/osv"
)

// testCache for testing purposes
type testCache struct {
	indexMap   map[string]DBIndex
	indexStamp map[string]time.Time
	vulnMap    map[string]map[string][]*osv.Entry
}

func newTestCache() *testCache {
	return &testCache{
		indexMap:   make(map[string]DBIndex),
		indexStamp: make(map[string]time.Time),
		vulnMap:    make(map[string]map[string][]*osv.Entry),
	}
}

func (tc *testCache) ReadIndex(db string) (DBIndex, time.Time, error) {
	index, ok := tc.indexMap[db]
	if !ok {
		return nil, time.Time{}, nil
	}
	stamp, ok := tc.indexStamp[db]
	if !ok {
		return nil, time.Time{}, nil
	}
	return index, stamp, nil
}

func (tc *testCache) WriteIndex(db string, index DBIndex, stamp time.Time) error {
	tc.indexMap[db] = index
	tc.indexStamp[db] = stamp
	return nil
}

func (tc *testCache) ReadEntries(db, module string) ([]*osv.Entry, error) {
	mMap, ok := tc.vulnMap[db]
	if !ok {
		return nil, nil
	}
	return mMap[module], nil
}

func (tc *testCache) WriteEntries(db, module string, entries []*osv.Entry) error {
	mMap, ok := tc.vulnMap[db]
	if !ok {
		mMap = make(map[string][]*osv.Entry)
		tc.vulnMap[db] = mMap
	}
	mMap[module] = nil
	for _, e := range entries {
		e2 := *e
		e2.Details = "cached: " + e2.Details
		mMap[module] = append(mMap[module], &e2)
	}
	return nil
}

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
		cache        Cache
		detailPrefix string
		wantVulns    int
	}{
		// Test the http client without any cache.
		{name: "http-no-cache", source: srv.URL, module: modulePath,
			cache: nil, detailPrefix: detailStart, wantVulns: 3},
		{name: "http-cache", source: srv.URL, module: modulePath,
			cache: newTestCache(), detailPrefix: "cached: Route", wantVulns: 3},
		// Repeat the same for local file client.
		{name: "file-no-cache", source: localURL, module: modulePath,
			cache: nil, detailPrefix: detailStart, wantVulns: 3},
		// Cache does not play a role in local file databases.
		{name: "file-cache", source: localURL, module: modulePath,
			cache: newTestCache(), detailPrefix: detailStart, wantVulns: 3},
		// Test all-lowercase module path.
		{name: "lower-http", source: srv.URL, module: modulePathLowercase,
			cache: nil, detailPrefix: detailStartLowercase, wantVulns: 4},
		{name: "lower-file", source: localURL, module: modulePathLowercase,
			cache: nil, detailPrefix: detailStartLowercase, wantVulns: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient([]string{test.source}, Options{HTTPCache: test.cache})
			if err != nil {
				t.Fatal(err)
			}

			// First call fills cache, if present.
			if _, err := client.GetByModule(ctx, test.module); err != nil {
				t.Fatal(err)
			}
			vulns, err := client.GetByModule(ctx, test.module)
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
//     request in GetByModule.
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
	for _, cache := range []Cache{newTestCache(), nil} {
		clt, err := NewClient([]string{srv.URL}, Options{HTTPCache: cache})
		if err != nil {
			t.Fatal(err)
		}
		hs := clt.(*client).sources[0].(*httpSource)
		for _, modulePath := range modulePaths {
			indexCalls := hs.indexCalls
			httpCalls := hs.httpCalls
			if _, err := clt.GetByModule(ctx, modulePath); err != nil {
				t.Fatal(err)
			}
			// Number of index Calls should be increased.
			if hs.indexCalls == indexCalls {
				t.Errorf("GetByModule(ctx, %s) [cache:%t] did not call Index(...)", modulePath, cache != nil)
			}
			// If http request was made, then the modulePath must be in the index.
			if hs.httpCalls > httpCalls {
				index, err := hs.Index(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_, present := index[modulePath]
				if !present {
					t.Errorf("GetByModule(ctx, %s) [cache:%t] issued http request for module not in Index(...)", modulePath, cache != nil)
				}
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
			client, err := NewClient([]string{test.source}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			for specialPath := range specialCaseModulePaths {
				t.Run(test.name+"-"+specialPath, func(t *testing.T) {
					if _, err := client.GetByModule(ctx, specialPath); err != nil {
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
		if _, err := hs.GetByModule(context.Background(), module); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
	expectedFetches := map[string]int{"/index.json": 3,
		"/m.com/a.json": 1, "/m.com/b.json": 1}
	if !reflect.DeepEqual(fetches, expectedFetches) {
		t.Errorf("unexpected fetches, got %v, want %v", fetches, expectedFetches)
	}
}

// Make sure that a cached index is used in the case it is stale
// but there were no changes to it at the server side.
func TestCorrectFetchesNoChangeIndex(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer ts.Close()
	url, _ := url.Parse(ts.URL)

	// set timestamp so that cached index is stale,
	// i.e., more than two hours old.
	timeStamp := time.Now().Add(time.Hour * (-3))
	index := DBIndex{"a": timeStamp}
	cache := newTestCache()
	cache.WriteIndex(url.Hostname(), index, timeStamp)

	e := &osv.Entry{
		ID:       "ID1",
		Details:  "details",
		Modified: timeStamp,
	}
	cache.WriteEntries(url.Hostname(), "a", []*osv.Entry{e})

	client, err := NewClient([]string{ts.URL}, Options{HTTPCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	gots, err := client.GetByModule(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(gots) != 1 {
		t.Errorf("got %d vulns, want 1", len(gots))
	} else {
		got := gots[0]
		want := *e
		want.Details = "cached: " + want.Details
		if !cmp.Equal(got, &want) {
			t.Errorf("\ngot %+v\nwant %+v", got, &want)
		}
	}
}

func TestClientByID(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}

	const vulnID = "GO-2022-0463"
	want := mustReadEntry(t, vulnID)
	srv := newTestServer()
	defer srv.Close()

	for _, test := range []struct {
		name   string
		source string
		in     string
		want   *osv.Entry
	}{
		{name: "http", in: vulnID, source: srv.URL, want: want},
		{name: "file", in: vulnID, source: localURL, want: want},
		{name: "http", in: "NO-SUCH-VULN", source: srv.URL, want: nil},
		{name: "http", in: "NO-SUCH-VULN", source: localURL, want: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient([]string{test.source}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.GetByID(context.Background(), vulnID)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, want) {
				t.Errorf("got\n%+v\nwant\n%+v", got, want)
			}
		})
	}
}

func mustReadEntry(t *testing.T, vulnID string) *osv.Entry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vulndb", internal.IDDirectory, vulnID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var e *osv.Entry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestClientByAlias(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}
	const alias = "CVE-2015-5739"
	want := []*osv.Entry{mustReadEntry(t, "GO-2021-0157"), mustReadEntry(t, "GO-2021-0159")}
	srv := newTestServer()
	defer srv.Close()
	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "http", source: srv.URL},
		{name: "file", source: localURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient([]string{test.source}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.GetByAlias(context.Background(), alias)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, want) {
				t.Errorf("got\n%+v\nwant\n%+v", got, want)
			}
		})
	}
}

func TestListIDs(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}

	srv := newTestServer()
	defer srv.Close()

	want := []string{"GO-2022-0463", "GO-2022-0569", "GO-2022-0572"}
	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "http", source: srv.URL},
		{name: "file", source: localURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient([]string{test.source}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.ListIDs(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, want) {
				t.Errorf("got\n%+v\nwant\n%+v", got, want)
			}
		})
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
			client, err := NewClient([]string{test.source}, Options{})
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
