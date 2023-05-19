// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"strings"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

func TestFrame(t *testing.T) {
	for _, test := range []struct {
		name     string
		frame    *govulncheck.Frame
		short    bool
		wantFunc string
		wantPos  string
	}{
		{
			name: "position and function",
			frame: &govulncheck.Frame{
				Package:  "golang.org/x/vuln/internal/vulncheck",
				Function: "Foo",
				Position: &govulncheck.Position{Filename: "some/path/file.go", Line: 12},
			},
			wantFunc: "golang.org/x/vuln/internal/vulncheck.Foo",
			wantPos:  "some/path/file.go:12",
		},
		{
			name: "receiver",
			frame: &govulncheck.Frame{
				Package:  "golang.org/x/vuln/internal/vulncheck",
				Receiver: "Bar",
				Function: "Foo",
			},
			wantFunc: "golang.org/x/vuln/internal/vulncheck.Bar.Foo",
		},
		{
			name:     "function and receiver",
			frame:    &govulncheck.Frame{Receiver: "*ServeMux", Function: "Handle"},
			wantFunc: "ServeMux.Handle",
		},
		{
			name:     "package and function",
			frame:    &govulncheck.Frame{Package: "net/http", Function: "Get"},
			wantFunc: "net/http.Get",
		},
		{
			name:     "package, function and receiver",
			frame:    &govulncheck.Frame{Package: "net/http", Receiver: "*ServeMux", Function: "Handle"},
			wantFunc: "net/http.ServeMux.Handle",
		},
		{
			name:     "short",
			frame:    &govulncheck.Frame{Package: "net/http", Function: "Get"},
			short:    true,
			wantFunc: "http.Get",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := &strings.Builder{}
			addSymbolName(buf, test.frame, test.short)
			got := buf.String()
			if got != test.wantFunc {
				t.Errorf("want %v func name; got %v", test.wantFunc, got)
			}
			if got := posToString(test.frame.Position); got != test.wantPos {
				t.Errorf("want %v call position; got %v", test.wantPos, got)
			}
		})
	}
}

func TestVuln(t *testing.T) {
	// vuln creates a Vuln with symbol info syms.
	// Each element of syms is a pair <p, s> where
	// p is both the module and package path, and
	// s is the called symbol. If s is "", then
	// there is no called symbol.
	vuln := func(syms ...[2]string) []*govulncheck.Finding {
		result := []*govulncheck.Finding{}
		for _, sym := range syms {
			result = append(result, &govulncheck.Finding{
				OSV:          "",
				FixedVersion: "",
				Trace: []*govulncheck.Frame{{
					Module:   sym[0],
					Package:  sym[0],
					Function: sym[1],
					Position: &govulncheck.Position{},
				}},
			})
		}
		return result
	}

	for _, test := range []struct {
		desc string
		v    []*govulncheck.Finding
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
