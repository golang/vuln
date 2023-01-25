// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/vuln/vulncheck"
)

// compact replaces consecutive runs of equal elements with a single copy.
// This is like the uniq command found on Unix.
// compact modifies the contents of the slice s; it does not create a new slice.
//
// Modified (generics removed) from exp/slices/slices.go.
func compact(s []string) []string {
	if len(s) == 0 {
		return s
	}
	i := 1
	last := s[0]
	for _, v := range s[1:] {
		if v != last {
			s[i] = v
			i++
			last = v
		}
	}
	return s[:i]
}

func moduleVersionString(modulePath, version string) string {
	if version == "" {
		return ""
	}
	return fmt.Sprintf("%s@%s", modulePath, version)
}

// indent returns the output of prefixing n spaces to s at every line break,
// except for empty lines. See TestIndent for examples.
func indent(s string, n int) string {
	b := []byte(s)
	var result []byte
	shouldAppend := true
	prefix := strings.Repeat(" ", n)
	for _, c := range b {
		if shouldAppend && c != '\n' {
			result = append(result, prefix...)
		}
		result = append(result, c)
		shouldAppend = c == '\n'
	}
	return string(result)
}

// depPkgsAndMods returns the number of packages that
// topPkgs depend on and the number of their modules.
func depPkgsAndMods(topPkgs []*vulncheck.Package) (int, int) {
	tops := make(map[string]bool)
	depPkgs := make(map[string]bool)
	depMods := make(map[string]bool)

	for _, t := range topPkgs {
		tops[t.PkgPath] = true
	}

	var visit func(*vulncheck.Package, bool)
	visit = func(p *vulncheck.Package, top bool) {
		path := p.PkgPath
		if depPkgs[path] {
			return
		}
		if tops[path] && !top {
			// A top package that is a dependency
			// will not be in depPkgs, so we skip
			// reiterating on it here.
			return
		}

		// We don't count a top-level package as
		// a dependency even when they are used
		// as a dependent package.
		if !tops[path] {
			depPkgs[path] = true
			if p.Module != nil { // no module for stdlib
				depMods[p.Module.Path] = true
			}
		}

		for _, d := range p.Imports {
			visit(d, false)
		}
	}

	for _, t := range topPkgs {
		visit(t, true)
	}

	return len(depPkgs), len(depMods)
}

// govulncheckVersion reconstructs the current version of
// govulncheck used from the build info.
func govulncheckVersion(bi *debug.BuildInfo) string {
	var r, t string
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			r = "-" + s.Value[:12]
		}
		if s.Key == "vcs.time" {
			// commit time is of the form 2023-01-25T19:57:54Z
			p, err := time.Parse(time.RFC3339, s.Value)
			if err == nil {
				t = "-" + p.Format("20060102150405")
			}
		}
	}
	// TODO: we manually change this after every
	// minor revision? bi.Main.Version seems not
	// to work (see #29228).
	return "v0.0.0" + r + t
}
