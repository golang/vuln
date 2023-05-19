// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"testing"

	"golang.org/x/vuln/internal/osv"
)

func TestLatestFixed(t *testing.T) {
	for _, test := range []struct {
		name   string
		module string
		in     []osv.Affected
		want   string
	}{
		{
			name: "empty",
			want: "",
		},
		{
			name:   "no semver",
			module: "example.com/module",
			in: []osv.Affected{
				{
					Module: osv.Module{
						Path: "example.com/module",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeType("unspecified"),
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
							},
						}},
				},
			},
			want: "",
		},
		{
			name:   "one",
			module: "example.com/module",
			in: []osv.Affected{
				{
					Module: osv.Module{
						Path: "example.com/module",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeTypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
							},
						}},
				},
			},
			want: "v1.2.3",
		},
		{
			name:   "several",
			module: "example.com/module",
			in: []osv.Affected{
				{
					Module: osv.Module{
						Path: "example.com/module",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeTypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
								{Introduced: "v1.5.0", Fixed: "v1.5.6"},
							},
						}},
				},
				{
					Module: osv.Module{
						Path: "example.com/module",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeTypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.3.0", Fixed: "v1.4.1"},
							},
						}},
				},
				{
					// This should be ignored.
					Module: osv.Module{
						Path: "example.com/anothermodule",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeTypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "0", Fixed: "v1.6.0"},
							},
						}},
				},
			},
			want: "v1.5.6",
		},
		{
			name:   "no v prefix",
			module: "example.com/module",
			in: []osv.Affected{
				{
					Module: osv.Module{
						Path: "example.com/module",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeTypeSemver,
							Events: []osv.RangeEvent{
								{Fixed: "1.17.2"},
							},
						}},
				},
				{
					Module: osv.Module{
						Path: "example.com/module",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeTypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "1.18.0", Fixed: "1.18.4"},
							},
						}},
				},
			},
			want: "1.18.4",
		},
		{
			name:   "unfixed",
			module: "example.com/module",
			in: []osv.Affected{
				{
					Module: osv.Module{
						Path: "example.com/module",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeTypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
								// Reintroduced and never fixed.
								{Introduced: "v1.5.0"},
							},
						}},
				},
				{
					Module: osv.Module{
						Path: "example.com/module",
					},
					Ranges: []osv.Range{
						{
							Type: osv.RangeTypeSemver,
							Events: []osv.RangeEvent{
								// Even though this block has a fix,
								// it will be overridden by the block
								// with no fix.
								{Introduced: "v1.3.0", Fixed: "v1.4.1"},
							},
						}},
				},
			},
			want: "",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := latestFixed(test.module, test.in)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}
