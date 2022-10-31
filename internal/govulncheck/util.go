// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
	"golang.org/x/vuln/internal"
	isem "golang.org/x/vuln/internal/semver"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

// LatestFixed returns the latest fixed version in the list of affected ranges,
// or the empty string if there are no fixed versions.
//
// TODO: make private
func LatestFixed(as []osv.Affected) string {
	v := ""
	for _, a := range as {
		for _, r := range a.Ranges {
			if r.Type == osv.TypeSemver {
				for _, e := range r.Events {
					if e.Fixed != "" && (v == "" ||
						semver.Compare(isem.CanonicalizeSemverPrefix(e.Fixed), isem.CanonicalizeSemverPrefix(v)) > 0) {
						v = e.Fixed
					}
				}
			}
		}
	}
	return v
}

func foundVersion(modulePath string, moduleVersions map[string]string) string {
	var found string
	if v := moduleVersions[modulePath]; v != "" {
		found = versionString(modulePath, v[1:])
	}
	return found
}

func fixedVersion(modulePath string, affected []osv.Affected) string {
	fixed := LatestFixed(affected)
	if fixed != "" {
		fixed = versionString(modulePath, fixed)
	}
	return fixed
}

// versionString prepends a version string prefix (`v` or `go`
// depending on the modulePath) to the given semver-style version string.
func versionString(modulePath, version string) string {
	if version == "" {
		return ""
	}
	v := "v" + version
	if modulePath == internal.GoStdModulePath || modulePath == internal.GoCmdModulePath {
		return semverToGoTag(v)
	}
	return v
}

// SummarizeCallStack returns a short description of the call stack.
// It uses one of two forms, depending on what the lowest function F in topPkgs
// calls:
//   - If it calls a function V from the vulnerable package, then summarizeCallStack
//     returns "F calls V".
//   - If it calls a function G in some other package, which eventually calls V,
//     it returns "F calls G, which eventually calls V".
//
// If it can't find any of these functions, summarizeCallStack returns the empty string.
//
// TODO: make private
func SummarizeCallStack(cs CallStack, topPkgs map[string]bool, vulnPkg string) string {
	// Find the lowest function in the top packages.
	iTop := lowest(cs.Frames, func(e *StackFrame) bool {
		return topPkgs[e.PkgPath]
	})
	if iTop < 0 {
		print("1\n")
		return ""
	}
	// Find the highest function in the vulnerable package that is below iTop.
	iVuln := highest(cs.Frames[iTop+1:], func(e *StackFrame) bool {
		return e.PkgPath == vulnPkg
	})
	if iVuln < 0 {
		print("2\n")
		return ""
	}
	iVuln += iTop + 1 // adjust for slice in call to highest.
	topName := funcName(cs.Frames[iTop])
	topPos := AbsRelShorter(funcPos(cs.Frames[iTop]))
	if topPos != "" {
		topPos += ": "
	}
	vulnName := funcName(cs.Frames[iVuln])
	if iVuln == iTop+1 {
		return fmt.Sprintf("%s%s calls %s", topPos, topName, vulnName)
	}
	return fmt.Sprintf("%s%s calls %s, which eventually calls %s",
		topPos, topName, funcName(cs.Frames[iTop+1]), vulnName)
}

// highest returns the highest (one with the smallest index) entry in the call
// stack for which f returns true.
func highest(cs []*StackFrame, f func(e *StackFrame) bool) int {
	for i := 0; i < len(cs); i++ {
		if f(cs[i]) {
			return i
		}
	}
	return -1
}

// lowest returns the lowest (one with the largets index) entry in the call
// stack for which f returns true.
func lowest(cs []*StackFrame, f func(e *StackFrame) bool) int {
	for i := len(cs) - 1; i >= 0; i-- {
		if f(cs[i]) {
			return i
		}
	}
	return -1
}

// PkgPath returns the package path from fn.
//
// TODO: make private
func PkgPath(fn *vulncheck.FuncNode) string {
	if fn.PkgPath != "" {
		return fn.PkgPath
	}
	s := strings.TrimPrefix(fn.RecvType, "*")
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

// funcName returns the full qualified function name from fn,
// adjusted to remove pointer annotations.
func funcName(sf *StackFrame) string {
	var n string
	if sf.RecvType == "" {
		n = fmt.Sprintf("%s.%s", sf.PkgPath, sf.FuncName)
	} else {
		n = fmt.Sprintf("%s.%s", sf.RecvType, sf.FuncName)
	}
	return strings.TrimPrefix(n, "*")
}

// funcPos returns the position of the call in sf as string.
// If position is not available, return "".
func funcPos(sf *StackFrame) string {
	if sf.Position.IsValid() {
		return sf.Position.String()
	}
	return ""
}
