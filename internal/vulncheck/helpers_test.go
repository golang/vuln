// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"runtime"
	"sort"

	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/semver"
)

// newTestClient returns a client that reads
// a database with the following vulnerable symbols:
//
//	golang.org/amod/avuln.{VulnData.Vuln1, vulnData.Vuln2}
//	golang.org/bmod/bvuln.Vuln
//	archive/zip.OpenReader
func newTestClient() (*client.Client, error) {
	return client.NewInMemoryClient(
		[]*osv.Entry{
			{
				ID: "VA",
				Affected: []osv.Affected{{
					Module: osv.Module{Path: "golang.org/amod"},
					Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "1.0.4"}, {Introduced: "1.1.2"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{Packages: []osv.Package{{
						Path:    "golang.org/amod/avuln",
						Symbols: []string{"VulnData.Vuln1", "VulnData.Vuln2"}},
					}},
				}},
			},
			{
				ID: "VB",
				Affected: []osv.Affected{{
					Module: osv.Module{Path: "golang.org/bmod"},
					Ranges: []osv.Range{{Type: osv.RangeTypeSemver}},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path:    "golang.org/bmod/bvuln",
							Symbols: []string{"Vuln"},
						}},
					},
				}},
			},
			{
				ID: "STD",
				Affected: []osv.Affected{{
					Module: osv.Module{Path: osv.GoStdModulePath},
					// Range is populated also using runtime info for testing binaries since
					// setting fixed Go version for binaries is very difficult.
					Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.18"}, {Introduced: semver.GoTagToSemver(runtime.Version())}}}},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path:    "archive/zip",
							Symbols: []string{"OpenReader"},
						}},
					},
				}},
			}})
}

type edge struct {
	// src and dest are ids of source and
	// destination nodes in a callgraph edge.
	src, dst string
}

func callGraphToStrMap(r *Result) map[string][]string {
	// seen edges, to avoid repetitions
	seen := make(map[edge]bool)
	m := make(map[string][]string)
	for _, v := range r.Vulns {
		updateCallGraph(m, v.CallSink, seen)
	}
	sortStrMap(m)
	return m
}

func updateCallGraph(callGraph map[string][]string, f *FuncNode, seen map[edge]bool) {
	fName := f.String()
	for _, callsite := range f.CallSites {
		e := edge{src: callsite.Parent.Name, dst: f.Name}
		if seen[e] {
			continue
		}
		seen[e] = true
		callerName := callsite.Parent.String()
		callGraph[callerName] = append(callGraph[callerName], fName)
		updateCallGraph(callGraph, callsite.Parent, seen)
	}
}

// sortStrMap sorts the map string slice values to make them deterministic.
func sortStrMap(m map[string][]string) {
	for _, strs := range m {
		sort.Strings(strs)
	}
}
