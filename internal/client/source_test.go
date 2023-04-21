// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"net/url"
	"os"
	"testing"

	"golang.org/x/vuln/internal/osv"
)

func TestGet(t *testing.T) {
	tcs := []struct {
		endpoint string
	}{
		{
			endpoint: "index/db",
		},
		{
			endpoint: "index/modules",
		},
		{
			endpoint: "ID/GO-2021-0068",
		},
	}
	for _, tc := range tcs {
		test := func(t *testing.T, s source) {
			got, err := s.get(context.Background(), tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(testVulndb + "/" + tc.endpoint + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("get(%s) = %s, want %s", tc.endpoint, got, want)
			}
		}
		testAllSourceTypes(t, test)
	}
}

// testAllSourceTypes runs a given test for all source types.
func testAllSourceTypes(t *testing.T, test func(t *testing.T, s source)) {
	t.Run("http", func(t *testing.T) {
		srv := newTestServer(testVulndb)
		hs := newHTTPSource(srv.URL, &Options{HTTPClient: srv.Client()})
		test(t, hs)
	})

	t.Run("local", func(t *testing.T) {
		uri, err := url.Parse(testVulndbFileURL)
		if err != nil {
			t.Fatal(err)
		}

		fs, err := newLocalSource(uri)
		if err != nil {
			t.Fatal(err)
		}

		test(t, fs)
	})

	t.Run("in-memory", func(t *testing.T) {
		testEntries, err := entries(testIDs)
		if err != nil {
			t.Fatal(err)
		}

		ms, err := newInMemorySource(testEntries)
		if err != nil {
			t.Fatal(err)
		}

		test(t, ms)
	})
}

func TestLatestFixedVersion(t *testing.T) {
	tests := []struct {
		name   string
		ranges []osv.Range
		want   string
	}{
		{
			name:   "empty",
			ranges: []osv.Range{},
			want:   "",
		},
		{
			name: "no fix",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{
						Introduced: "0",
					},
				},
			}},
			want: "",
		},
		{
			name: "no latest fix",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{Introduced: "0"},
					{Fixed: "1.0.4"},
					{Introduced: "1.1.2"},
				},
			}},
			want: "",
		},
		{
			name: "unsorted no latest fix",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{Fixed: "1.0.4"},
					{Introduced: "0"},
					{Introduced: "1.1.2"},
					{Introduced: "1.5.0"},
					{Fixed: "1.1.4"},
				},
			}},
			want: "",
		},
		{
			name: "unsorted with fix",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{
						Fixed: "1.0.0",
					},
					{
						Introduced: "0",
					},
					{
						Fixed: "0.1.0",
					},
					{
						Introduced: "0.5.0",
					},
				},
			}},
			want: "1.0.0",
		},
		{
			name: "multiple ranges",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{
						Introduced: "0",
					},
					{
						Fixed: "0.1.0",
					},
				},
			},
				{
					Type: osv.RangeTypeSemver,
					Events: []osv.RangeEvent{
						{
							Introduced: "0",
						},
						{
							Fixed: "0.2.0",
						},
					},
				}},
			want: "0.2.0",
		},
		{
			name: "pseudoversion",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{
						Introduced: "0",
					},
					{
						Fixed: "0.0.0-20220824120805-abc",
					},
					{
						Introduced: "0.0.0-20230824120805-efg",
					},
					{
						Fixed: "0.0.0-20240824120805-hij",
					},
				},
			}},
			want: "0.0.0-20240824120805-hij",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := latestFixedVersion(test.ranges)
			if got != test.want {
				t.Errorf("latestFixedVersion = %q, want %q", got, test.want)
			}
		})
	}
}
