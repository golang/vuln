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
func Run(ctx context.Context, cfg Config) (*Result, error) {
	dbs := []string{vulndbHost}
	if db := os.Getenv(envGOVULNDB); db != "" {
		dbs = strings.Split(db, ",")
	}
	dbClient, err := client.NewClient(dbs, client.Options{
		HTTPCache: DefaultCache(),
	})
	if err != nil {
		return nil, err
	}
	vcfg := &vulncheck.Config{Client: dbClient, SourceGoVersion: cfg.GoVersion}

	format := cfg.OutputType
	if format == OutputTypeText || format == OutputTypeVerbose {
		fmt.Println(introMessage)
	}
	var (
		r          *vulncheck.Result
		pkgs       []*vulncheck.Package
		unaffected []*vulncheck.Vuln
	)
	switch cfg.AnalysisType {
	case AnalysisTypeBinary:
		f, err := os.Open(cfg.Patterns[0])
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r, err = binary(ctx, f, vcfg)
		if err != nil {
			return nil, err
		}
	case AnalysisTypeSource:
		pkgs, err = loadPackages(cfg)
		if err != nil {
			// Try to provide a meaningful and actionable error message.
			if !fileExists(filepath.Join(cfg.SourceLoadConfig.Dir, "go.mod")) {
				return nil, ErrNoGoMod
			}
			if !fileExists(filepath.Join(cfg.SourceLoadConfig.Dir, "go.sum")) {
				return nil, ErrNoGoSum
			}
			if isGoVersionMismatchError(err) {
				return nil, fmt.Errorf("%v\n\n%v", ErrGoVersionMismatch, err)
			}
			return nil, err
		}

		// Sort pkgs so that the PkgNodes returned by vulncheck.Source will be
		// deterministic.
		sortPackages(pkgs)
		r, err = vulncheck.Source(ctx, pkgs, vcfg)
		if err != nil {
			return nil, err
		}
		// TODO(https://go.dev/issue/56042): add affected and unaffected logic
		// to Result.
		unaffected = filterUnaffected(r)
		r.Vulns = filterCalled(r)
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAnalysisType, cfg.AnalysisType)
	}

	switch cfg.OutputType {
	case OutputTypeJSON:
		// Following golang.org/x/tools/go/analysis/singlechecker,
		// return 0 exit code in -json mode.

		// TODO(https://go.dev/issue/56042): change output from
		// vulncheck.Result to govulncheck.Result.
		if err := writeJSON(r); err != nil {
			return nil, err
		}
		return &Result{}, nil
	case OutputTypeSummary:
		// TODO(https://go.dev/issue/56042): delete this mode and change -json
		// to output govulncheck.Result
		ci := getCallInfo(r, pkgs)
		if err := writeJSON(summary(ci, unaffected)); err != nil {
			return nil, err
		}
		return &Result{}, nil
	case OutputTypeText, OutputTypeVerbose:
		// set of top-level packages, used to find representative symbols

		// TODO(https://go.dev/issue/56042): add callinfo to govulncheck.Result
		// See comments from http://go.dev/cl/437856.
		ci := getCallInfo(r, pkgs)

		// TODO(https://go.dev/issue/56042): move fields from output to Result
		// struct and delete writeText.
		writeText(r, ci, unaffected, cfg.OutputType == OutputTypeVerbose)
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidOutputType, cfg.OutputType)
	}
	if len(r.Vulns) > 0 {
		return nil, ErrContainsVulnerabilties
	}
	return &Result{}, nil
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

func writeText(r *vulncheck.Result, ci *callInfo, unaffected []*vulncheck.Vuln, verbose bool) {
	// TODO(https://go.dev/issue/56042): add uniqueVulns to govulncheck.Result.
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
	for idx, vg := range ci.vulnGroups {
		fmt.Println()
		// All the vulns in vg have the same PkgPath, ModPath and OSV.
		// All have a non-zero CallSink.

		// TODO(https://go.dev/issue/56042): add ID, details, found and fixed
		// below to govulncheck.Result.
		v0 := vg[0]
		id := v0.OSV.ID
		details := wrap(v0.OSV.Details, 80-labelWidth)
		found := packageVersionString(v0.PkgPath, foundVersion(v0.ModPath, ci))
		fixed := packageVersionString(v0.PkgPath, fixedVersion(v0.ModPath, v0.OSV.Affected))

		// TODO(https://go.dev/issue/56042): add stacks to govulncheck.Result.
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
		// TODO(https://go.dev/issue/56042): add platform and callstack summary
		// to govulncheck.Result
		writeVulnerability(idx+1, id, details, b.String(), found, fixed, platforms(v0.OSV))
	}
	if len(unaffected) > 0 {
		fmt.Println()
		fmt.Println(informationalMessage)
		for idx, vuln := range unaffected {
			found := packageVersionString(vuln.PkgPath, foundVersion(vuln.ModPath, ci))
			fixed := packageVersionString(vuln.PkgPath, fixedVersion(vuln.ModPath, vuln.OSV.Affected))
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

func foundVersion(modulePath string, ci *callInfo) string {
	var found string
	if v := ci.moduleVersions[modulePath]; v != "" {
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

func defaultCallStacks(vg []*vulncheck.Vuln, ci *callInfo) string {
	var summaries []string
	for _, v := range vg {
		if css := ci.callStacks[v]; len(css) > 0 {
			if sum := SummarizeCallStack(css[0], ci.topPackages, v.PkgPath); sum != "" {
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

func verboseCallStacks(vg []*vulncheck.Vuln, ci *callInfo) string {
	// Display one full call stack for each vuln.
	i := 1
	nMore := 0
	var b strings.Builder
	for _, v := range vg {
		css := ci.callStacks[v]
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
	if version == "" {
		return ""
	}
	return fmt.Sprintf("%s@%s", packagePath, version)
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
