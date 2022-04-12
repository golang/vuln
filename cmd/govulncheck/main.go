// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

// Command govulncheck reports known vulnerabilities filed in a vulnerability database
// (see https://golang.org/design/draft-vulndb) that affect a given package or binary.
//
// It uses static analysis or the binary's symbol table to narrow down reports to only
// those that potentially affect the application.
//
// # WARNING WARNING WARNING
//
// govulncheck is still experimental and neither its output or the vulnerability
// database should be relied on to be stable or comprehensive.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/build"
	"log"
	"os"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

var (
	jsonFlag    = flag.Bool("json", false, "")
	verboseFlag = flag.Bool("v", false, "")
	testsFlag   = flag.Bool("tests", false, "")
	htmlFlag    = flag.Bool("html", false, "")
)

const usage = `govulncheck: identify known vulnerabilities by call graph traversal.

Usage:

	govulncheck [flags] {package pattern...}

	govulncheck [flags] {binary path}

Flags:

	-json	Print vulnerability findings in JSON format.

	-html	Generate HTML with the vulnerability findings.

	-tags	Comma-separated list of build tags.

	-tests	Boolean flag indicating if test files should be analyzed too.

govulncheck can be used with either one or more package patterns (i.e. golang.org/x/crypto/...
or ./...) or with a single path to a Go binary. In the latter case module and symbol
information will be extracted from the binary in order to detect vulnerable symbols.

The environment variable GOVULNDB can be set to a comma-separated list of vulnerability
database URLs, with http://, https://, or file:// protocols. Entries from multiple
databases are merged.
`

func init() {
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

func main() {
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if len(flag.Args()) == 0 {
		die("%s", usage)
	}

	dbs := []string{"https://vuln.go.dev"}
	if GOVULNDB := os.Getenv("GOVULNDB"); GOVULNDB != "" {
		dbs = strings.Split(GOVULNDB, ",")
	}
	dbClient, err := client.NewClient(dbs, client.Options{HTTPCache: defaultCache()})
	if err != nil {
		die("govulncheck: %s", err)
	}
	vcfg := &vulncheck.Config{Client: dbClient}
	ctx := context.Background()

	patterns := flag.Args()
	var (
		r     *vulncheck.Result
		pkgs  []*packages.Package
		vulns []*vulncheck.Vuln
	)
	if len(patterns) == 1 && isFile(patterns[0]) {
		f, err := os.Open(patterns[0])
		if err != nil {
			die("govulncheck: %v", err)
		}
		defer f.Close()
		r, err = vulncheck.Binary(ctx, f, vcfg)
		if err != nil {
			die("govulncheck: %v", err)
		}
		vulns = r.Vulns
	} else {
		cfg := &packages.Config{
			Mode:       packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedModule,
			Tests:      *testsFlag,
			BuildFlags: []string{fmt.Sprintf("-tags=%s", strings.Join(build.Default.BuildTags, ","))},
		}
		pkgs, err = loadPackages(cfg, patterns)
		if err != nil {
			die("govulncheck: %v", err)
		}
		r, err = vulncheck.Source(ctx, vulncheck.Convert(pkgs), vcfg)
		if err != nil {
			die("govulncheck: %v", err)
		}

		// Skip vulns that are in the import graph but have no calls to them.
		for _, v := range r.Vulns {
			if v.CallSink != 0 {
				vulns = append(vulns, v)
			}
		}
	}
	if *jsonFlag {
		writeJSON(r)
	} else {
		callStacks := vulncheck.CallStacks(r)
		// Create set of top-level packages, used to find representative symbols
		topPackages := map[string]bool{}
		for _, p := range pkgs {
			topPackages[p.PkgPath] = true
		}
		vulnGroups := groupByIDAndPackage(vulns)
		moduleVersions := moduleVersionMap(r.Modules)
		if *htmlFlag {
			if err := html(os.Stdout, r, callStacks, moduleVersions, topPackages, vulnGroups); err != nil {
				die("writing HTML: %v", err)
			}
		} else {
			writeText(r, callStacks, moduleVersions, topPackages, vulnGroups)
		}
	}
	exitCode := 0
	// Following go vet, fail with 3 if there are findings (in this case, vulns).
	if len(vulns) > 0 {
		exitCode = 3
	}
	os.Exit(exitCode)
}

// moduleVersionMap builds a map from module paths to versions.
func moduleVersionMap(mods []*vulncheck.Module) map[string]string {
	moduleVersions := map[string]string{}
	for _, m := range mods {
		v := m.Version
		if m.Replace != nil {
			v = m.Replace.Version
		}
		moduleVersions[m.Path] = v
	}
	return moduleVersions
}

func writeJSON(r *vulncheck.Result) {
	b, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		die("govulncheck: %s", err)
	}
	os.Stdout.Write(b)
	fmt.Println()
}

func writeText(r *vulncheck.Result, callStacks map[*vulncheck.Vuln][]vulncheck.CallStack, moduleVersions map[string]string, topPackages map[string]bool, vulnGroups [][]*vulncheck.Vuln) {

	const labelWidth = 16
	line := func(label, text string) {
		fmt.Printf("%-*s%s\n", labelWidth, label, text)
	}
	for _, vg := range vulnGroups {
		// All the vulns in vg have the same PkgPath, ModPath and OSV.
		// All have a non-zero CallSink.
		v0 := vg[0]
		line("package:", v0.PkgPath)
		line("your version:", moduleVersions[v0.ModPath])
		line("fixed version:", "v"+latestFixed(v0.OSV.Affected))
		var summaries []string
		for _, v := range vg {
			if css := callStacks[v]; len(css) > 0 {
				if sum := summarizeCallStack(css[0], topPackages, v.PkgPath); sum != "" {
					summaries = append(summaries, sum)
				}
			}
		}
		if len(summaries) > 0 {
			sort.Strings(summaries)
			summaries = compact(summaries)
			line("sample call stacks:", "")
			for _, s := range summaries {
				line("", s)
			}
		}
		line("reference:", fmt.Sprintf("https://pkg.go.dev/vuln/%s", v0.OSV.ID))
		desc := strings.Split(wrap(v0.OSV.Details, 80-labelWidth), "\n")
		for i, l := range desc {
			if i == 0 {
				line("description:", l)
			} else {
				line("", l)
			}
		}
		fmt.Println()
	}
}

func groupByIDAndPackage(vs []*vulncheck.Vuln) [][]*vulncheck.Vuln {
	groups := map[[2]string][]*vulncheck.Vuln{}
	for _, v := range vs {
		key := [2]string{v.OSV.ID, v.PkgPath}
		groups[key] = append(groups[key], v)
	}

	var res [][]*vulncheck.Vuln
	for _, g := range groups {
		res = append(res, g)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i][0].PkgPath < res[j][0].PkgPath
	})
	return res
}

func packageModule(p *packages.Package) *packages.Module {
	m := p.Module
	if m == nil {
		return nil
	}
	if r := m.Replace; r != nil {
		return r
	}
	return m
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}

func loadPackages(cfg *packages.Config, patterns []string) ([]*packages.Package, error) {
	if *verboseFlag {
		log.Println("loading packages...")
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("packages contain errors")
	}
	if *verboseFlag {
		log.Printf("\t%d loaded packages\n", len(pkgs))
	}
	return pkgs, nil
}

// latestFixed returns the latest fixed version in the list of affected ranges,
// or the empty string if there are no fixed versions.
func latestFixed(as []osv.Affected) string {
	v := ""
	for _, a := range as {
		for _, r := range a.Ranges {
			if r.Type == osv.TypeSemver {
				for _, e := range r.Events {
					if e.Fixed != "" && (v == "" || semver.Compare(e.Fixed, v) > 0) {
						v = e.Fixed
					}
				}
			}
		}
	}
	return v
}

// summarizeCallStack returns a short description of the call stack.
// It uses one of two forms, depending on what the lowest function F in topPkgs
// calls:
//   - If it calls a function V from the vulnerable package, then summarizeCallStack
//     returns "F calls V".
//   - If it calls a function G in some other package, which eventually calls V,
//     it returns "F calls G, which eventually calls V".
//
// If it can't find any of these functions, summarizeCallStack returns the empty string.
func summarizeCallStack(cs vulncheck.CallStack, topPkgs map[string]bool, vulnPkg string) string {
	// Find the lowest function in the top packages.
	iTop := lowest(cs, func(e vulncheck.StackEntry) bool {
		return topPkgs[pkgPath(e.Function)]
	})
	if iTop < 0 {
		return ""
	}
	// Find the highest function in the vulnerable package that is below iTop.
	iVuln := highest(cs[iTop+1:], func(e vulncheck.StackEntry) bool {
		return pkgPath(e.Function) == vulnPkg
	})
	if iVuln < 0 {
		return ""
	}
	iVuln += iTop + 1 // adjust for slice in call to highest.
	topName := funcName(cs[iTop].Function)
	vulnName := funcName(cs[iVuln].Function)
	if iVuln == iTop+1 {
		return fmt.Sprintf("%s calls %s", topName, vulnName)
	}
	return fmt.Sprintf("%s calls %s, which eventually calls %s",
		topName, funcName(cs[iTop+1].Function), vulnName)
}

// highest returns the highest (one with the smallest index) entry in the call
// stack for which f returns true.
func highest(cs vulncheck.CallStack, f func(e vulncheck.StackEntry) bool) int {
	for i := 0; i < len(cs); i++ {
		if f(cs[i]) {
			return i
		}
	}
	return -1
}

// lowest returns the lowest (one with the largets index) entry in the call
// stack for which f returns true.
func lowest(cs vulncheck.CallStack, f func(e vulncheck.StackEntry) bool) int {
	for i := len(cs) - 1; i >= 0; i-- {
		if f(cs[i]) {
			return i
		}
	}
	return -1
}

func pkgPath(fn *vulncheck.FuncNode) string {
	if fn.PkgPath != "" {
		return fn.PkgPath
	}
	s := strings.TrimPrefix(fn.RecvType, "*")
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

func funcName(fn *vulncheck.FuncNode) string {
	return strings.TrimPrefix(fn.String(), "*")
}

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

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
