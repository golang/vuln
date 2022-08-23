// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/cmd/govulncheck/internal/govulncheck"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

var (
	jsonFlag    = flag.Bool("json", false, "")
	verboseFlag = flag.Bool("v", false, "")
	testsFlag   = flag.Bool("tests", false, "")
	htmlFlag    = flag.Bool("html", false, "")
)

const usage = `Command govulncheck identifies functions and methods in Go
source code with known vulnerabilities.

govulncheck can be used to analyze source code with one or more package
patterns (for example, golang.org/x/crypto/...  or ./...), or on a single Go
binary. For Go binaries, module and symbol information will be extracted from
the binary to detect vulnerable symbols.

By default, govulncheck makes requests to the Go vulnerability database
(https://vuln.go.dev). The environment variable GOVULNDB can be set to a
comma-separated list of vulnerability database URLs, with http://, https://, or
file:// protocols. Entries from multiple databases are merged.

For more information, visit https://go.dev/security/vulndb.

Usage:

	govulncheck [flags] {package pattern...}

	govulncheck [flags] {binary path} (if built with Go 1.18 or higher)

Flags:

	-v	Print a full call stack for each vulnerability.

	-json	Print vulnerability findings in JSON format.

	-html	Generate HTML with the vulnerability findings.

	-tags	Comma-separated list of build tags.

	-tests	Boolean flag indicating if test files should be analyzed too.
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
	dbClient, err := client.NewClient(dbs, client.Options{
		HTTPCache: govulncheck.DefaultCache(),
	})
	if err != nil {
		die("govulncheck: %s", err)
	}
	vcfg := &vulncheck.Config{Client: dbClient, SourceGoVersion: goVersion()}

	patterns := flag.Args()
	if !(*jsonFlag || *htmlFlag) {
		fmt.Printf(`govulncheck is an experimental tool. Share feedback at https://go.dev/s/govulncheck-feedback.

Scanning for dependencies with known vulnerabilities...
`)
	}
	var (
		r              *vulncheck.Result
		pkgs           []*vulncheck.Package
		unaffectedMods map[string][]string
		ctx            = context.Background()
	)
	if len(patterns) == 1 && isFile(patterns[0]) {
		f, err := os.Open(patterns[0])
		if err != nil {
			die("govulncheck: %v", err)
		}
		defer f.Close()
		r, err = binary(ctx, f, vcfg)
		if err != nil {
			die("govulncheck: %v", err)
		}
	} else {
		cfg := &packages.Config{
			Tests:      *testsFlag,
			BuildFlags: []string{fmt.Sprintf("-tags=%s", strings.Join(build.Default.BuildTags, ","))},
		}
		pkgs, err = govulncheck.LoadPackages(cfg, patterns...)
		if err != nil {
			// Check if the error is due to the fact that
			// the current project is not a module.
			if !fileExists("go.mod") {
				die("govulncheck: missing go.mod file?")
			}
			die("govulncheck: %v", err)
		}

		// Sort pkgs so that the PkgNodes returned by vulncheck.Source will be
		// deterministic.
		sort.Slice(pkgs, func(i, j int) bool {
			return pkgs[i].PkgPath < pkgs[j].PkgPath
		})
		for _, pkg := range pkgs {
			sort.Slice(pkg.Imports, func(i, j int) bool {
				return pkg.Imports[i].PkgPath < pkg.Imports[j].PkgPath
			})
		}
		r, err = vulncheck.Source(ctx, pkgs, vcfg)
		if err != nil {
			die("govulncheck: %v", err)
		}
		unaffectedMods = filterUnaffected(r.Vulns)
		r.Vulns = filterCalled(r)
	}

	if *jsonFlag {
		writeJSON(r)
	} else {
		// set of top-level packages, used to find representative symbols
		ci := govulncheck.GetCallInfo(r, pkgs)
		if *htmlFlag {
			if err := html(os.Stdout, ci); err != nil {
				die("writing HTML: %v", err)
			}
		} else {
			writeText(r, ci, unaffectedMods)
		}
	}
	exitCode := 0
	// Following go vet, fail with 3 if there are findings (in this case, vulns).
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
	return vulns
}

// filterUnaffected returns vulnerabilities where no symbols are called,
// grouped by module.
func filterUnaffected(vulns []*vulncheck.Vuln) map[string][]string {
	// It is possible that the same vuln.OSV.ID has vuln.CallSink != 0
	// for one symbol, but vuln.CallSink == 0 for a different one, so
	// we need to filter out ones that have been called.
	called := map[string]bool{}
	for _, vuln := range vulns {
		if vuln.CallSink != 0 {
			called[vuln.OSV.ID] = true
		}
	}

	modToIDs := map[string]map[string]bool{}
	for _, vuln := range vulns {
		if !called[vuln.OSV.ID] {
			if _, ok := modToIDs[vuln.ModPath]; !ok {
				modToIDs[vuln.ModPath] = map[string]bool{}
			}
			modToIDs[vuln.ModPath][vuln.OSV.ID] = true
		}
	}
	output := map[string][]string{}
	for m, idSet := range modToIDs {
		for id := range idSet {
			output[m] = append(output[m], id)
		}
		sort.Strings(output[m])
	}
	return output
}

func writeJSON(r *vulncheck.Result) {
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

func writeText(r *vulncheck.Result, ci *govulncheck.CallInfo, unaffectedMods map[string][]string) {
	uniqueVulns := map[string]bool{}
	for _, v := range r.Vulns {
		uniqueVulns[v.OSV.ID] = true
	}
	switch len(uniqueVulns) {
	case 0:
		fmt.Println("No vulnerabilities found.")
		return
	case 1:
		fmt.Println("Found 1 known vulnerability.")
	default:
		fmt.Printf("Found %d known vulnerabilities.\n", len(uniqueVulns))
	}
	fmt.Println()
	for idx, vg := range ci.VulnGroups {
		// All the vulns in vg have the same PkgPath, ModPath and OSV.
		// All have a non-zero CallSink.
		v0 := vg[0]
		id := v0.OSV.ID
		details := wrap(v0.OSV.Details, 80-labelWidth)
		found := foundVersion(v0.ModPath, v0.PkgPath, ci)
		fixed := fixedVersion(v0.PkgPath, v0.OSV.Affected)

		var stacks string
		if !*verboseFlag {
			stacks = defaultCallStacks(vg, ci)
		} else {
			stacks = verboseCallStacks(vg, ci)
		}
		var b strings.Builder
		if len(stacks) > 0 {
			b.WriteString(indent("\nCall stacks in your code:\n", 4))
			b.WriteString(indent(stacks, 6))
		}
		writeVulnerability(idx+1, id, details, b.String(), found, fixed)
	}
	if len(unaffectedMods) > 0 {
		fmt.Println()
		fmt.Println(strings.Repeat("-", lineLength))
		fmt.Println()
		fmt.Println(wrap("These vulnerabilities exist in required modules, but no vulnerable symbols are used. No action is required. For more information, visit https://pkg.go.dev/vuln.", 80-labelWidth))
		fmt.Println()
		for m, ids := range unaffectedMods {
			fmt.Printf("%s (%s)\n", m, strings.Join(ids, ", "))
		}
		fmt.Println()
	}
	fmt.Println()
}

func writeVulnerability(idx int, id, details, callstack, found, fixed string) {
	if fixed == "" {
		fixed = "N/A"
	}
	fmt.Printf(`Vulnerability #%d: %s
%s%s
  Found in: %s
  Fixed in: %s
  More info: https://pkg.go.dev/vuln/%s
`, idx, id, indent(details, 2), callstack, found, fixed, id)
}

func foundVersion(modulePath, pkgPath string, ci *govulncheck.CallInfo) string {
	var found string
	if v := ci.ModuleVersions[modulePath]; v != "" {
		found = packageVersionString(pkgPath, v[1:])
	}
	return found
}

func fixedVersion(pkgPath string, affected []osv.Affected) string {
	fixed := govulncheck.LatestFixed(affected)
	if fixed != "" {
		fixed = packageVersionString(pkgPath, fixed)
	}
	return fixed
}

func defaultCallStacks(vg []*vulncheck.Vuln, ci *govulncheck.CallInfo) string {
	var summaries []string
	for _, v := range vg {
		if css := ci.CallStacks[v]; len(css) > 0 {
			if sum := govulncheck.SummarizeCallStack(css[0], ci.TopPackages, v.PkgPath); sum != "" {
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

func verboseCallStacks(vg []*vulncheck.Vuln, ci *govulncheck.CallInfo) string {
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
			b.WriteString(fmt.Sprintf("  %s\n", govulncheck.FuncName(e.Function)))
			if e.Call != nil && e.Call.Pos != nil {
				b.WriteString(fmt.Sprintf("      %s\n", e.Call.Pos.String()))
			}
		}
		i++
		nMore += len(css) - 1
	}
	if nMore > 0 {
		b.WriteString(fmt.Sprintf("    There are %d more call stacks available.\n", nMore))
		b.WriteString(fmt.Sprintf("To see all of them, pass the -json or -html flags.\n"))
	}
	return b.String()
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}

// fileExists checks if file path exists. Returns true
// if the file exists or it cannot prove that it does
// not exist. Otherwise, returns false.
func fileExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	}
	// Conservatively return true if os.Stat fails
	// for some other reason.
	return true
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
