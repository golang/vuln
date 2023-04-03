// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"go/token"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

func TestStackFrame(t *testing.T) {
	for _, test := range []struct {
		sf       *govulncheck.StackFrame
		wantFunc string
		wantPos  string
	}{
		{
			&govulncheck.StackFrame{
				Package:  "golang.org/x/vuln/internal/vulncheck",
				Function: "Foo",
				Position: token.Position{Filename: "some/path/file.go", Line: 12},
			},
			"golang.org/x/vuln/internal/vulncheck.Foo",
			"some/path/file.go:12",
		},
		{
			&govulncheck.StackFrame{
				Package:  "golang.org/x/vuln/internal/vulncheck",
				Receiver: "golang.org/x/vuln/internal/vulncheck.Bar",
				Function: "Foo",
			},
			"golang.org/x/vuln/internal/vulncheck.Bar.Foo",
			"",
		},
	} {
		if got := FuncName(test.sf); got != test.wantFunc {
			t.Errorf("want %v func name; got %v", test.wantFunc, got)
		}
		if got := Pos(test.sf); got != test.wantPos {
			t.Errorf("want %v call position; got %v", test.wantPos, got)
		}
	}
}

func TestVuln(t *testing.T) {
	// vuln creates a Vuln with symbol info syms.
	// Each element of syms is a pair <p, s> where
	// p is both the module and package path, and
	// s is the called symbol. If s is "", then
	// there is no called symbol.
	vuln := func(syms ...[2]string) *govulncheck.Vuln {
		v := &govulncheck.Vuln{}
		for _, sym := range syms {
			p := &govulncheck.Package{Path: sym[0]}
			v.Modules = append(v.Modules, &govulncheck.Module{
				Path:     sym[0],
				Packages: []*govulncheck.Package{p},
			})
			if symbol := sym[1]; symbol != "" {
				cs := govulncheck.CallStack{Symbol: symbol}
				p.CallStacks = []govulncheck.CallStack{cs}
			}
		}
		return v
	}

	for _, test := range []struct {
		desc string
		v    *govulncheck.Vuln
		want bool
	}{
		{"called - single module", vuln([2]string{"golang.org/p1", "Foo"}), true},
		{"called - multi modules", vuln([2]string{"golang.org/p1", "Foo"}, [2]string{"golang.org/p2", "Bar"}), true},
		// The following case is not expected to happen in practice, but we check it for sanity.
		{"called - mixed multi modules", vuln([2]string{"golang.org/p1", ""}, [2]string{"golang.org/p2", "Bar"}), true},
		{"not called - single module", vuln([2]string{"golang.org/p1", ""}), false},
		{"not called - multi modules", vuln([2]string{"golang.org/p1", ""}, [2]string{"golang.org/p2", ""}), false},
	} {
		if IsCalled(test.v) != test.want {
			t.Errorf("want called=%t for %v; got the opposite", test.want, test.desc)
		}
	}
}

func TestFuncName(t *testing.T) {
	for _, test := range []struct {
		name  string
		frame *govulncheck.StackFrame
		want  string
	}{
		{
			"function and receiver",
			&govulncheck.StackFrame{Receiver: "*ServeMux", Function: "Handle"},
			"ServeMux.Handle",
		},
		{
			"package and function",
			&govulncheck.StackFrame{Package: "net/http", Function: "Get"},
			"net/http.Get",
		},
		{
			"package, function and receiver",
			&govulncheck.StackFrame{Package: "net/http", Receiver: "*ServeMux", Function: "Handle"},
			"ServeMux.Handle",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := FuncName(test.frame)
			if got != test.want {
				t.Errorf("got = %q; want = %q", got, test.want)
			}
		})
	}
}
