// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/test"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

func TestUniqueCallStack(t *testing.T) {
	a := &vulncheck.FuncNode{Name: "A"}
	b := &vulncheck.FuncNode{Name: "B"}
	v1 := &vulncheck.FuncNode{Name: "V1"}
	v2 := &vulncheck.FuncNode{Name: "V2"}
	v3 := &vulncheck.FuncNode{Name: "V3"}

	vuln1 := &vulncheck.Vuln{Symbol: "V1", CallSink: 1}
	vuln2 := &vulncheck.Vuln{Symbol: "V2", CallSink: 2}
	vuln3 := &vulncheck.Vuln{Symbol: "V3", CallSink: 3}

	vr := &vulncheck.Result{
		Calls: &vulncheck.CallGraph{
			Functions: map[int]*vulncheck.FuncNode{1: v1, 2: v2, 3: v3},
		},
		Vulns: []*vulncheck.Vuln{vuln1, vuln2, vuln3},
	}

	callStack := func(fs ...*vulncheck.FuncNode) vulncheck.CallStack {
		var cs vulncheck.CallStack
		for _, f := range fs {
			cs = append(cs, vulncheck.StackEntry{Function: f})
		}
		return cs
	}

	// V1, V2, and V3 are vulnerable symbols
	skip := []*vulncheck.Vuln{vuln1, vuln2, vuln3}
	for _, test := range []struct {
		vuln *vulncheck.Vuln
		css  []vulncheck.CallStack
		want vulncheck.CallStack
	}{
		// [A -> B -> V3 -> V1, A -> V1] ==> A -> V1 since the first stack goes through V3
		{vuln1, []vulncheck.CallStack{callStack(a, b, v3, v1), callStack(a, v1)}, callStack(a, v1)},
		// [A -> V1 -> V2] ==> nil since the only candidate call stack goes through V1
		{vuln2, []vulncheck.CallStack{callStack(a, v1, v2)}, nil},
		// [A -> V1 -> V3, A -> B -> v3] ==> A -> B -> V3 since the first stack goes through V1
		{vuln3, []vulncheck.CallStack{callStack(a, v1, v3), callStack(a, b, v3)}, callStack(a, b, v3)},
	} {
		t.Run(test.vuln.Symbol, func(t *testing.T) {
			got := uniqueCallStack(test.vuln, test.css, skip, vr)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestSummarizeCallStack(t *testing.T) {
	topPkgs := map[string]bool{"t1": true, "t2": true}
	vulnPkg := "v"

	for _, test := range []struct {
		in, want string
	}{
		{"a.F", ""},
		{"t1.F", ""},
		{"v.V", ""},
		{
			"t1.F v.V",
			"t1.F calls v.V",
		},
		{
			"t1.F t2.G v.V1 v.v2",
			"t2.G calls v.V1",
		},
		{
			"t1.F x.Y t2.G a.H b.I c.J v.V",
			"t2.G calls a.H, which eventually calls v.V",
		},
	} {
		in := stringToCallStack(test.in)
		got := summarizeCallStack(in, topPkgs, vulnPkg)
		if got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.in, got, test.want)
		}
	}
}

func stringToCallStack(s string) CallStack {
	var cs CallStack
	for _, e := range strings.Fields(s) {
		parts := strings.Split(e, ".")
		cs.Frames = append(cs.Frames, &StackFrame{
			PkgPath:  parts[0],
			FuncName: parts[1],
		})
	}
	return cs
}

// TestInits checks for correct positions of init functions
// and their respective calls (see #51575).
func TestInits(t *testing.T) {
	testClient := &test.MockClient{
		Ret: map[string][]*osv.Entry{
			"golang.org/amod": []*osv.Entry{
				{
					ID: "A", Affected: []osv.Affected{{Package: osv.Package{Name: "golang.org/amod"}, Ranges: osv.Affects{{Type: osv.TypeSemver}},
						EcosystemSpecific: osv.EcosystemSpecific{Imports: []osv.EcosystemSpecificImport{{
							Path: "golang.org/amod/avuln", Symbols: []string{"A"}},
						}},
					}},
				},
			},
			"golang.org/cmod": []*osv.Entry{
				{
					ID: "C", Affected: []osv.Affected{{Package: osv.Package{Name: "golang.org/cmod"}, Ranges: osv.Affects{{Type: osv.TypeSemver}},
						EcosystemSpecific: osv.EcosystemSpecific{Imports: []osv.EcosystemSpecificImport{{
							Path: "golang.org/cmod/cvuln", Symbols: []string{"C"}},
						}},
					}},
				},
			},
		},
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
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatal("failed to load x test package")
	}
	vpkgs := vulncheck.Convert(pkgs)
	result, err := vulncheck.Source(context.Background(), vpkgs, &vulncheck.Config{Client: testClient})
	if err != nil {
		t.Fatal(err)
	}

	cs := vulncheck.CallStacks(result)
	updateInitPositions(cs, vpkgs)

	want := map[string][][]string{
		"A": [][]string{{
			// Entry init's position is the package statement.
			// It calls avuln.init at avuln import statement.
			"N:golang.org/entry/x.init	F:x.go:2:4	C:x.go:5:5",
			// implicit avuln.init is calls explicit init at the avuln
			// package statement.
			"N:golang.org/amod/avuln.init	F:avuln.go:2:4	C:avuln.go:2:4",
			"N:golang.org/amod/avuln.init#1	F:avuln.go:4:9	C:avuln.go:5:6",
			"N:golang.org/amod/avuln.A	F:avuln.go:8:9	C:",
		}},
		"C": [][]string{{
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

				sse := fmt.Sprintf("N:%s.%s\tF:%v\tC:%v", se.Function.PkgPath, se.Function.Name, fp, cp)
				scs = append(scs, sse)
			}
			scss = append(scss, scs)
		}
		m[v.OSV.ID] = scss
	}
	return m
}
