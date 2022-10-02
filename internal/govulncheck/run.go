// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

// Run is the main function for the govulncheck command line tool.
func Run(cfg Config) error {
	dbs := []string{vulndbHost}
	if db := os.Getenv(envGOVULNDB); db != "" {
		dbs = strings.Split(db, ",")
	}
	dbClient, err := client.NewClient(dbs, client.Options{
		HTTPCache: DefaultCache(),
	})
	if err != nil {
		return err
	}
	vcfg := &vulncheck.Config{Client: dbClient, SourceGoVersion: internal.GoVersion()}

	patterns := cfg.Patterns
	format := cfg.OutputType
	if format == OutputTypeText || format == OutputTypeVerbose {
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
	switch cfg.AnalysisType {
	case AnalysisTypeBinary:
		f, err := os.Open(patterns[0])
		if err != nil {
			return err
		}
		defer f.Close()
		r, err = binary(ctx, f, vcfg)
		if err != nil {
			return err
		}
	case AnalysisTypeSource:
		cfg := &cfg.SourceLoadConfig
		pkgs, err = LoadPackages(cfg, patterns...)
		if err != nil {
			// Try to provide a meaningful and actionable error message.
			if !fileExists(filepath.Join(cfg.Dir, "go.mod")) {
				return ErrNoGoMod
			}
			if !fileExists(filepath.Join(cfg.Dir, "go.sum")) {
				return ErrNoGoSum
			}
			if isGoVersionMismatchError(err) {
				return fmt.Errorf("%v\n\n%v", ErrGoVersionMismatch, err)
			}
			return err
		}

		// Sort pkgs so that the PkgNodes returned by vulncheck.Source will be
		// deterministic.
		sortPackages(pkgs)
		r, err = vulncheck.Source(ctx, pkgs, vcfg)
		if err != nil {
			return err
		}
		unaffected = filterUnaffected(r)
		r.Vulns = filterCalled(r)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidAnalysisType, cfg.AnalysisType)
	}

	switch format {
	case OutputTypeJSON:
		// Following golang.org/x/tools/go/analysis/singlechecker,
		// return 0 exit code in -json mode.
		return writeJSON(r)
	case OutputTypeText, OutputTypeVerbose:
		// set of top-level packages, used to find representative symbols
		ci := GetCallInfo(r, pkgs)
		writeText(r, ci, unaffected, format == OutputTypeVerbose)
	case OutputTypeSummary:
		ci := GetCallInfo(r, pkgs)
		return writeJSON(summary(ci, unaffected))
	default:
		return fmt.Errorf("%w: %s", ErrInvalidOutputType, cfg.OutputType)
	}
	if len(r.Vulns) > 0 {
		return ErrContainsVulnerabilties
	}
	return nil
}

func writeJSON(r any) error {
	b, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		return err
	}
	os.Stdout.Write(b)
	fmt.Println()
	return nil
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

func packageVersionString(packagePath, version string) string {
	v := "v" + version
	if importPathInStdlib(packagePath) {
		v = semverToGoTag(v)
	}
	return fmt.Sprintf("%s@%s", packagePath, v)
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
