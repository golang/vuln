// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

// Config is the configuration for Main.
type Config struct {
	// Analysis specifies the vulncheck analysis type. Valid types are "source" and "binary"
	Analysis string
	// OutputFormat specifies the result type. Valid types are:
	//  "text": print human readable compact text output to STDOUT.
	//  "verbose": print human readable verbose text output to STDOUT.
	//  "json": print JSON-encoded vulncheck.Result.
	//  "summary": print JSON-encoded Summary.
	OutputFormat string

	// Patterns are either the binary path for "binary" analysis mode, or
	// go package patterns for "source" analysis mode.
	Patterns []string

	// SourceLoadConfig specifies the package loading configuration.
	SourceLoadConfig packages.Config
}

// Main is the main function for the govulncheck command line tool.
func Main(cfg Config) {
	dbs := []string{"https://vuln.go.dev"}
	if GOVULNDB := os.Getenv("GOVULNDB"); GOVULNDB != "" {
		dbs = strings.Split(GOVULNDB, ",")
	}
	dbClient, err := client.NewClient(dbs, client.Options{
		HTTPCache: DefaultCache(),
	})
	if err != nil {
		die("govulncheck: %s", err)
	}
	vcfg := &vulncheck.Config{Client: dbClient, SourceGoVersion: goVersion()}

	patterns := cfg.Patterns
	format := cfg.OutputFormat
	if format == "text" || format == "verbose" {
		fmt.Printf(`govulncheck is an experimental tool. Share feedback at https://go.dev/s/govulncheck-feedback.

Scanning for dependencies with known vulnerabilities...
`)
	}
	var (
		r          *vulncheck.Result
		pkgs       []*vulncheck.Package
		unaffected []*vulncheck.Vuln
		ctx        = context.Background()
	)
	switch cfg.Analysis {
	case "binary":
		f, err := os.Open(patterns[0])
		if err != nil {
			die("govulncheck: %v", err)
		}
		defer f.Close()
		r, err = binary(ctx, f, vcfg)
		if err != nil {
			die("govulncheck: %v", err)
		}
	case "source":
		cfg := &cfg.SourceLoadConfig
		pkgs, err = LoadPackages(cfg, patterns...)
		if err != nil {
			// Try to provide a meaningful and actionable error message.
			if !fileExists(filepath.Join(cfg.Dir, "go.mod")) {
				die(noGoModErrorMessage)
			} else if !fileExists(filepath.Join(cfg.Dir, "go.sum")) {
				die(noGoSumErrorMessage)
			} else if isGoVersionMismatchError(err) {
				die(fmt.Sprintf("%s\n\n%v", goVersionMismatchErrorMessage, err))
			}
			die("govulncheck: %v", err)
		}

		// Sort pkgs so that the PkgNodes returned by vulncheck.Source will be
		// deterministic.
		sortPackages(pkgs)
		r, err = vulncheck.Source(ctx, pkgs, vcfg)
		if err != nil {
			die("govulncheck: %v", err)
		}
		unaffected = filterUnaffected(r)
		r.Vulns = filterCalled(r)
	default:
		die("govulncheck: invalid analysis mode %q", cfg.Analysis)
	}

	switch format {
	case "json":
		// Following golang.org/x/tools/go/analysis/singlechecker,
		// return 0 exit code in -json mode.
		writeJSON(r)
		os.Exit(0)
	case "text", "verbose":
		// set of top-level packages, used to find representative symbols
		ci := GetCallInfo(r, pkgs)
		writeText(r, ci, unaffected, format == "verbose")
	case "summary":
		ci := GetCallInfo(r, pkgs)
		writeJSON(summary(ci, unaffected))
		os.Exit(0)
	default:
		die("govulncheck: unrecognized output type %q", cfg.OutputFormat)
	}

	// Following golang.org/x/tools/go/analysis/singlechecker,
	// fail with 3 if there are findings (in this case, vulns).
	exitCode := 0
	if len(r.Vulns) > 0 {
		exitCode = 3
	}
	os.Exit(exitCode)
}

// filterCalled returns vulnerabilities where the symbols are actually called.
func filterCalled(r *vulncheck.Result) []*vulncheck.Vuln {
	var vulns []*vulncheck.Vuln
	for _, v := range r.Vulns {
		if v.CallSink != 0 {
			vulns = append(vulns, v)
		}
	}
	sortVulns(vulns)
	return vulns
}

// filterUnaffected returns vulnerabilities where no symbols are called,
// grouped by module.
func filterUnaffected(r *vulncheck.Result) []*vulncheck.Vuln {
	// It is possible that the same vuln.OSV.ID has vuln.CallSink != 0
	// for one symbol, but vuln.CallSink == 0 for a different one, so
	// we need to filter out ones that have been called.
	called := filterCalled(r)
	calledIDs := map[string]bool{}
	for _, vuln := range called {
		calledIDs[vuln.OSV.ID] = true
	}

	idToVuln := map[string]*vulncheck.Vuln{}
	for _, vuln := range r.Vulns {
		if !calledIDs[vuln.OSV.ID] {
			idToVuln[vuln.OSV.ID] = vuln
		}
	}
	var output []*vulncheck.Vuln
	for _, vuln := range idToVuln {
		output = append(output, vuln)
	}
	sortVulns(output)
	return output
}

func sortVulns(vulns []*vulncheck.Vuln) {
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].OSV.ID > vulns[j].OSV.ID
	})
}

func sortPackages(pkgs []*vulncheck.Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].PkgPath < pkgs[j].PkgPath
	})
	for _, pkg := range pkgs {
		sort.Slice(pkg.Imports, func(i, j int) bool {
			return pkg.Imports[i].PkgPath < pkg.Imports[j].PkgPath
		})
	}
}

func writeJSON(r any) {
	b, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		die("govulncheck: %s", err)
	}
	os.Stdout.Write(b)
	fmt.Println()
}

const (
	labelWidth = 16
	lineLength = 55
)

func writeText(r *vulncheck.Result, ci *CallInfo, unaffected []*vulncheck.Vuln, verbose bool) {
	uniqueVulns := map[string]bool{}
	for _, v := range r.Vulns {
		uniqueVulns[v.OSV.ID] = true
	}
	switch len(uniqueVulns) {
	case 0:
		fmt.Println("No vulnerabilities found.")
	case 1:
		fmt.Println("Found 1 known vulnerability.")
	default:
		fmt.Printf("Found %d known vulnerabilities.\n", len(uniqueVulns))
	}
	for idx, vg := range ci.VulnGroups {
		fmt.Println()
		// All the vulns in vg have the same PkgPath, ModPath and OSV.
		// All have a non-zero CallSink.
		v0 := vg[0]
		id := v0.OSV.ID
		details := wrap(v0.OSV.Details, 80-labelWidth)
		found := foundVersion(v0.ModPath, v0.PkgPath, ci)
		fixed := fixedVersion(v0.PkgPath, v0.OSV.Affected)

		var stacks string
		if !verbose {
			stacks = defaultCallStacks(vg, ci)
		} else {
			stacks = verboseCallStacks(vg, ci)
		}
		var b strings.Builder
		if len(stacks) > 0 {
			b.WriteString(indent("\n\nCall stacks in your code:\n", 2))
			b.WriteString(indent(stacks, 6))
		}
		writeVulnerability(idx+1, id, details, b.String(), found, fixed, platforms(v0.OSV))
	}
	if len(unaffected) > 0 {
		fmt.Printf(`
=== Informational ===

The vulnerabilities below are in packages that you import, but your code
doesn't appear to call any vulnerable functions. You may not need to take any
action. See https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
for details.
`)
		for idx, vuln := range unaffected {
			found := foundVersion(vuln.ModPath, vuln.PkgPath, ci)
			fixed := fixedVersion(vuln.PkgPath, vuln.OSV.Affected)
			fmt.Println()
			writeVulnerability(idx+1, vuln.OSV.ID, vuln.OSV.Details, "", found, fixed, platforms(vuln.OSV))
		}
	}
}

func writeVulnerability(idx int, id, details, callstack, found, fixed, platforms string) {
	if fixed == "" {
		fixed = "N/A"
	}
	if platforms != "" {
		platforms = "  Platforms: " + platforms + "\n"
	}
	fmt.Printf(`Vulnerability #%d: %s
%s%s
  Found in: %s
  Fixed in: %s
%s  More info: https://pkg.go.dev/vuln/%s
`, idx, id, indent(details, 2), callstack, found, fixed, platforms, id)
}

func foundVersion(modulePath, pkgPath string, ci *CallInfo) string {
	var found string
	if v := ci.ModuleVersions[modulePath]; v != "" {
		found = packageVersionString(pkgPath, v[1:])
	}
	return found
}

func fixedVersion(pkgPath string, affected []osv.Affected) string {
	fixed := LatestFixed(affected)
	if fixed != "" {
		fixed = packageVersionString(pkgPath, fixed)
	}
	return fixed
}

func defaultCallStacks(vg []*vulncheck.Vuln, ci *CallInfo) string {
	var summaries []string
	for _, v := range vg {
		if css := ci.CallStacks[v]; len(css) > 0 {
			if sum := SummarizeCallStack(css[0], ci.TopPackages, v.PkgPath); sum != "" {
				summaries = append(summaries, strings.TrimSpace(sum))
			}
		}
	}
	if len(summaries) > 0 {
		sort.Strings(summaries)
		summaries = compact(summaries)
	}
	var b strings.Builder
	for _, s := range summaries {
		b.WriteString(s)
		b.WriteString("\n")
	}
	return b.String()
}

func verboseCallStacks(vg []*vulncheck.Vuln, ci *CallInfo) string {
	// Display one full call stack for each vuln.
	i := 1
	nMore := 0
	var b strings.Builder
	for _, v := range vg {
		css := ci.CallStacks[v]
		if len(css) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("#%d: for function %s\n", i, v.Symbol))
		for _, e := range css[0] {
			b.WriteString(fmt.Sprintf("  %s\n", FuncName(e.Function)))
			if pos := AbsRelShorter(FuncPos(e.Call)); pos != "" {
				b.WriteString(fmt.Sprintf("      %s\n", pos))
			}
		}
		i++
		nMore += len(css) - 1
	}
	if nMore > 0 {
		b.WriteString(fmt.Sprintf("    There are %d more call stacks available.\n", nMore))
		b.WriteString(fmt.Sprintf("To see all of them, pass the -json flags.\n"))
	}
	return b.String()
}

// platforms returns a string describing the GOOS/GOARCH pairs that the vuln affects.
// If it affects all of them, it returns the empty string.
func platforms(e *osv.Entry) string {
	platforms := map[string]bool{}
	for _, a := range e.Affected {
		for _, p := range a.EcosystemSpecific.Imports {
			for _, os := range p.GOOS {
				for _, arch := range p.GOARCH {
					platforms[os+"/"+arch] = true
				}
			}
		}
	}
	keys := maps.Keys(platforms)
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
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

func goVersion() string {
	if v := os.Getenv("GOVERSION"); v != "" {
		// Unlikely to happen in practice, mostly used for testing.
		return v
	}
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to determine go version; skipping stdlib scanning: %v\n", err)
		return ""
	}
	return string(bytes.TrimSpace(out))
}

func packageVersionString(packagePath, version string) string {
	v := "v" + version
	if importPathInStdlib(packagePath) {
		v = semverToGoTag(v)
	}
	return fmt.Sprintf("%s@%s", packagePath, v)
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
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
