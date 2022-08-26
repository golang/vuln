// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"encoding/json"
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

const localURL = "file://testdata/vulndb"

func TestByModule(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}
	ctx := context.Background()
	// Create a local http database.
	srv := newTestServer()
	defer srv.Close()

	const (
		modulePath  = "github.com/beego/beego"
		detailStart = "Routes in the beego HTTP router"
	)
	for _, test := range []struct {
		name         string
		source       string
		cache        Cache
		detailPrefix string
	}{
		// Test the http client without any cache.
		{name: "http-no-cache", source: srv.URL, cache: nil, detailPrefix: detailStart},
		// TODO(golang/go#54698): uncomment when caching is fixed.
		// {name: "http-cache", source: srv.URL, cache: newTestCache(), detailPrefix: "cached: Route"},
		// Repeat the same for local file client.
		{name: "file-no-cache", source: localURL, cache: nil, detailPrefix: detailStart},
		// Cache does not play a role in local file databases.
		{name: "file-cache", source: localURL, cache: newTestCache(), detailPrefix: detailStart},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient([]string{test.source}, Options{HTTPCache: test.cache})
			if err != nil {
				t.Fatal(err)
			}

			// First call fills cache, if present.
			if _, err := client.GetByModule(ctx, modulePath); err != nil {
				t.Fatal(err)
			}
			vulns, err := client.GetByModule(ctx, modulePath)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := len(vulns), 3; got != want {
				t.Errorf("got %d vulns for %s, want %d", got, modulePath, want)
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

func TestCorrectFetchesNoCache(t *testing.T) {
	fetches := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches[r.URL.Path]++
		if r.URL.Path == "/index.json" {
			j, _ := json.Marshal(DBIndex{
				"a": time.Now(),
				"b": time.Now(),
			})
			w.Write(j)
		} else {
			w.Write([]byte("[]"))
		}
	}))
	defer ts.Close()

	hs := &httpSource{url: ts.URL, c: new(http.Client)}
	for _, module := range []string{"a", "b", "c"} {
		if _, err := hs.GetByModule(context.Background(), module); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
	expectedFetches := map[string]int{"/index.json": 3, "/a.json": 1, "/b.json": 1}
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
	var want *osv.Entry
	wantData, err := os.ReadFile(filepath.Join("testdata", "vulndb", internal.IDDirectory, vulnID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wantData, &want); err != nil {
		t.Fatal(err)
	}

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
	want := info.ModTime().Round(time.Second).In(time.UTC)
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
			got = got.Round(time.Second)
			if !got.Equal(want) {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}
