// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	_ "embed"
)

//go:embed preamble.tmpl
var introTemplate string

//go:embed output.tmpl
var outputTemplate string

// tmplResult is a structure containing summarized
// govulncheck.Result, passed to outputTemplate.
type tmplResult []tmplVulnInfo

func (r tmplResult) AffectedCount() int {
	count := 0
	for _, a := range r {
		if a.Affected {
			count++
		}
	}
	return count
}

func (r tmplResult) UnaffectedCount() int {
	count := 0
	for _, a := range r {
		if !a.Affected {
			count++
		}
	}
	return count
}

// AffectedModules returns the number of unique modules
// whose vulnerabilties are detected.
func (r tmplResult) AffectedModules() int {
	mods := make(map[string]bool)
	for _, a := range r {
		if !a.Affected {
			continue
		}
		for _, m := range a.Modules {
			if !m.IsStd {
				mods[m.Module] = true
			}
		}
	}
	return len(mods)
}

// StdlibAffected tells if some of the vulnerabilities
// detected come from standard library.
func (r tmplResult) StdlibAffected() bool {
	for _, a := range r {
		if !a.Affected {
			continue
		}
		for _, m := range a.Modules {
			if m.IsStd {
				return true
			}
		}
	}
	return false
}

// tmplVulnInfo is a vulnerability info
// structure used by the outputTemplate.
type tmplVulnInfo struct {
	ID       string
	Details  string
	Modules  []tmplModVulnInfo
	Affected bool
}

// tmplModVulnInfo is a module vulnerability
// structure used by the outputTemplate.
type tmplModVulnInfo struct {
	IsStd     bool
	Module    string
	Found     string
	Fixed     string
	Platforms string
	Stacks    string
}
