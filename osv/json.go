// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package osv implements the OSV shared vulnerability
// format, as defined by https://github.com/ossf/osv-schema.
//
// As this package is intended for use with the Go vulnerability
// database, only the subset of features which are used by that
// database are implemented (for instance, only the SEMVER affected
// range type is implemented).
package osv

import (
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

type AffectsRangeType string

const (
	TypeUnspecified AffectsRangeType = "UNSPECIFIED"
	TypeGit         AffectsRangeType = "GIT"
	TypeSemver      AffectsRangeType = "SEMVER"
)

type Ecosystem string

const GoEcosystem Ecosystem = "Go"

type Package struct {
	Name      string    `json:"name"`
	Ecosystem Ecosystem `json:"ecosystem"`
}

type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type AffectsRange struct {
	Type   AffectsRangeType `json:"type"`
	Events []RangeEvent     `json:"events"`
}

// addSemverPrefix adds a 'v' prefix to s if it isn't already prefixed
// with 'v' or 'go'. This allows us to easily test go-style SEMVER
// strings against normal SEMVER strings.
func addSemverPrefix(s string) string {
	if !strings.HasPrefix(s, "v") && !strings.HasPrefix(s, "go") {
		return "v" + s
	}
	return s
}

func (ar AffectsRange) containsSemver(v string) bool {
	if ar.Type != TypeSemver {
		return false
	}
	if len(ar.Events) == 0 {
		return true
	}

	// Strip and then add the semver prefix so we can support bare versions,
	// versions prefixed with 'v', and versions prefixed with 'go'.
	v = canonicalizeSemverPrefix(v)

	var affected bool
	for _, e := range ar.Events {
		if !affected && e.Introduced != "" {
			affected = e.Introduced == "0" || semver.Compare(v, addSemverPrefix(e.Introduced)) >= 0
		} else if e.Fixed != "" {
			affected = semver.Compare(v, addSemverPrefix(e.Fixed)) < 0
		}
	}

	return affected
}

type Affects []AffectsRange

func (a Affects) AffectsSemver(v string) bool {
	if len(a) == 0 {
		// No ranges implies all versions are affected
		return true
	}
	var semverRangePresent bool
	for _, r := range a {
		if r.Type != TypeSemver {
			continue
		}
		semverRangePresent = true
		if r.containsSemver(v) {
			return true
		}
	}
	// If there were no semver ranges present we
	// assume that all semvers are affected, similarly
	// to how to we assume all semvers are affected
	// if there are no ranges at all.
	return !semverRangePresent
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Affected struct {
	Package           Package           `json:"package"`
	Ranges            Affects           `json:"ranges,omitempty"`
	DatabaseSpecific  DatabaseSpecific  `json:"database_specific"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

type DatabaseSpecific struct {
	URL string `json:"url"`
}

type EcosystemSpecific struct {
	Symbols []string `json:"symbols,omitempty"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
}

// Entry represents a OSV style JSON vulnerability database
// entry
type Entry struct {
	ID         string      `json:"id"`
	Published  time.Time   `json:"published"`
	Modified   time.Time   `json:"modified"`
	Withdrawn  *time.Time  `json:"withdrawn,omitempty"`
	Aliases    []string    `json:"aliases,omitempty"`
	Details    string      `json:"details"`
	Affected   []Affected  `json:"affected"`
	References []Reference `json:"references,omitempty"`
}

// removeSemverPrefix removes the 'v' or 'go' prefixes from go-style
// SEMVER strings, for usage in the public vulnerability format.
func removeSemverPrefix(s string) string {
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "go")
	return s
}

// canonicalizeSemverPrefix turns a SEMVER string into the canonical
// representation using the 'v' prefix, as used by the OSV format.
// Input may be a bare SEMVER ("1.2.3"), Go prefixed SEMVER ("go1.2.3"),
// or already canonical SEMVER ("v1.2.3").
func canonicalizeSemverPrefix(s string) string {
	return addSemverPrefix(removeSemverPrefix(s))
}
