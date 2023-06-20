// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/vulncheck"
)

func TestSummarizeCallStack(t *testing.T) {
	for _, test := range []struct {
		in, want string
	}{
		{"ma.a.F", "a.F"},
		{"m1.p1.F", "p1.F"},
		{"mv.v.V", "v.V"},
		{
			"m1.p1.F mv.v.V",
			"p1.F calls v.V",
		},
		{
			"m1.p1.F m1.p2.G mv.v.V1 mv.v.v2",
			"p2.G calls v.V1, which calls v.v2",
		},
		{
			"m1.p1.F m1.p2.G mv.v.V$1 mv.v.V1",
			"p2.G calls v.V, which calls v.V1",
		},
		{
			"m1.p1.F m1.p2.G$1 mv.v.V1",
			"p2.G calls v.V1",
		},
		{
			"m1.p1.F m1.p2.G$1 mv.v.V$1 mv.v.V1",
			"p2.G calls v.V, which calls v.V1",
		},
		{
			"m1.p1.F w.x.Y m1.p2.G ma.a.H mb.b.I mc.c.J mv.v.V",
			"p2.G calls a.H, which eventually calls v.V",
		},
		{
			"m1.p1.F w.x.Y m1.p2.G ma.a.H mb.b.I mc.c.J mv.v.V$1 mv.v.V1",
			"p2.G calls a.H, which eventually calls v.V1",
		},
		{
			"m1.p1.F m1.p1.F$1 ma.a.H mb.b.I mv.v.V1",
			"p1.F calls a.H, which eventually calls v.V1",
		},
	} {
		in := stringToFinding(test.in)
		got := compactTrace(in)
		if got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.in, got, test.want)
		}
	}
}

func stringToFinding(s string) *govulncheck.Finding {
	f := &govulncheck.Finding{}
	entries := strings.Fields(s)
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		firstDot := strings.Index(e, ".")
		lastDot := strings.LastIndex(e, ".")
		f.Trace = append(f.Trace, &govulncheck.Frame{
			Module:   e[:firstDot],
			Package:  e[:firstDot] + "/" + e[firstDot+1:lastDot],
			Function: e[lastDot+1:],
		})
	}
	return f
}

// TestInits checks for correct positions of init functions
// and their respective calls (see #51575).
func TestInits(t *testing.T) {
	testClient, err := client.NewInMemoryClient(
		[]*osv.Entry{
			{
				ID: "A", Affected: []osv.Affected{{Module: osv.Module{Path: "golang.org/amod"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver}},
					EcosystemSpecific: osv.EcosystemSpecific{Packages: []osv.Package{{
						Path: "golang.org/amod/avuln", Symbols: []string{"A"}},
					}},
				}},
			},
			{
				ID: "C", Affected: []osv.Affected{{Module: osv.Module{Path: "golang.org/cmod"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver}},
					EcosystemSpecific: osv.EcosystemSpecific{Packages: []osv.Package{{
						Path: "golang.org/cmod/cvuln", Symbols: []string{"C"}},
					}},
				}},
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import (
				_ "golang.org/amod/avuln"
				_ "golang.org/bmod/b"
			)
			`,
			},
		},
		{
			Name: "golang.org/amod@v0.5.0",
			Files: map[string]interface{}{"avuln/avuln.go": `
			package avuln

			func init() {
				A()
			}

			func A() {}
			`},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"b/b.go": `
			package b

			import _ "golang.org/cmod/cvuln"
			`},
		},
		{
			Name: "golang.org/cmod@v0.5.0",
			Files: map[string]interface{}{"cvuln/cvuln.go": `
			package cvuln

			var x int = C()

			func C() int {
				return 0
			}
			`},
		},
	})
	defer e.Cleanup()

	// Load x as entry package.
	graph := vulncheck.NewPackageGraph("go1.18")
	pkgs, err := graph.LoadPackages(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatal("failed to load x test package")
	}
	cfg := &govulncheck.Config{ScanLevel: "symbol"}
	result, err := vulncheck.Source(context.Background(), pkgs, cfg, testClient, graph)
	if err != nil {
		t.Fatal(err)
	}

	cs := vulncheck.CallStacks(result)
	updateInitPositions(cs)

	want := map[string][][]string{
		"A": {{
			// Entry init's position is the package statement.
			// It calls avuln.init at avuln import statement.
			"N:golang.org/entry/x.init	F:x.go:2:4	C:x.go:5:5",
			// implicit avuln.init is calls explicit init at the avuln
			// package statement.
			"N:golang.org/amod/avuln.init	F:avuln.go:2:4	C:avuln.go:2:4",
			"N:golang.org/amod/avuln.init#1	F:avuln.go:4:9	C:avuln.go:5:6",
			"N:golang.org/amod/avuln.A	F:avuln.go:8:9	C:",
		}},
		"C": {{
			"N:golang.org/entry/x.init	F:x.go:2:4	C:x.go:6:5",
			"N:golang.org/bmod/b.init	F:b.go:2:4	C:b.go:4:11",
			"N:golang.org/cmod/cvuln.init	F:cvuln.go:2:4	C:cvuln.go:4:17",
			"N:golang.org/cmod/cvuln.C	F:cvuln.go:6:9	C:",
		}},
	}
	if diff := cmp.Diff(want, strStacks(cs)); diff != "" {
		t.Errorf("modules mismatch (-want, +got):\n%s", diff)
	}
}

// strStacks creates a string representation of a call stacks map where
// vulnerability is represented with its ID and stack entry is a string
// "N:<package path.function name>  F:<function position> C:< call position>"
// File paths in positions consists of only file names.
func strStacks(callStacks map[*vulncheck.Vuln][]vulncheck.CallStack) map[string][][]string {
	m := make(map[string][][]string)
	for v, css := range callStacks {
		var scss [][]string
		for _, cs := range css {
			var scs []string
			for _, se := range cs {
				fPos := se.Function.Pos
				fp := fmt.Sprintf("%s:%d:%d", filepath.Base(fPos.Filename), fPos.Line, fPos.Column)

				var cp string
				if se.Call != nil && se.Call.Pos.IsValid() {
					cPos := se.Call.Pos
					cp = fmt.Sprintf("%s:%d:%d", filepath.Base(cPos.Filename), cPos.Line, cPos.Column)
				}

				sse := fmt.Sprintf("N:%s.%s\tF:%v\tC:%v", se.Function.Package.PkgPath, se.Function.Name, fp, cp)
				scs = append(scs, sse)
			}
			scss = append(scss, scs)
		}
		m[v.OSV.ID] = scss
	}
	return m
}
