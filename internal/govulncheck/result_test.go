// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"go/token"
	"testing"
)

func TestStackFrame(t *testing.T) {
	for _, test := range []struct {
		sf       *StackFrame
		wantFunc string
		wantPos  string
	}{
		{
			&StackFrame{
				PkgPath:  "golang.org/x/vuln/vulncheck",
				FuncName: "Foo",
				Position: token.Position{Filename: "some/path/file.go", Line: 12},
			},
			"golang.org/x/vuln/vulncheck.Foo",
			"some/path/file.go:12",
		},
		{
			&StackFrame{
				PkgPath:  "golang.org/x/vuln/vulncheck",
				RecvType: "golang.org/x/vuln/vulncheck.Bar",
				FuncName: "Foo",
			},
			"golang.org/x/vuln/vulncheck.Bar.Foo",
			"",
		},
	} {
		if got := test.sf.Name(); got != test.wantFunc {
			t.Errorf("want %v func name; got %v", test.wantFunc, got)
		}
		if got := test.sf.Pos(); got != test.wantPos {
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
	vuln := func(syms ...[2]string) *Vuln {
		v := &Vuln{}
		for _, sym := range syms {
			p := &Package{Path: sym[0]}
			v.Modules = append(v.Modules, &Module{
				Path:     sym[0],
				Packages: []*Package{p},
			})
			if symbol := sym[1]; symbol != "" {
				cs := CallStack{Symbol: symbol}
				p.CallStacks = []CallStack{cs}
			}
		}
		return v
	}

	for _, test := range []struct {
		desc string
		v    *Vuln
		want bool
	}{
		{"called - single module", vuln([2]string{"golang.org/p1", "Foo"}), true},
		{"called - multi modules", vuln([2]string{"golang.org/p1", "Foo"}, [2]string{"golang.org/p2", "Bar"}), true},
		// The following case is not expected to happen in practice, but we check it for sanity.
		{"called - mixed multi modules", vuln([2]string{"golang.org/p1", ""}, [2]string{"golang.org/p2", "Bar"}), true},
		{"not called - single module", vuln([2]string{"golang.org/p1", ""}), false},
		{"not called - multi modules", vuln([2]string{"golang.org/p1", ""}, [2]string{"golang.org/p2", ""}), false},
	} {
		if test.v.IsCalled() != test.want {
			t.Errorf("want called=%t for %v; got the opposite", test.want, test.desc)
		}
	}
}
