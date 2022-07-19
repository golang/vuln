// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
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

	govulncheck [flags] {binary path} (if built with Go 1.18 or higher)

Flags:

	-json	Print vulnerability findings in JSON format.

	-html	Generate HTML with the vulnerability findings.

	-tags	Comma-separated list of build tags.

	-tests	Boolean flag indicating if test files should be analyzed too.

govulncheck can be used with either one or more package patterns (i.e. golang.org/x/crypto/...
or ./...) or with a single path to a Go binary. In the latter case module and symbol
information will be extracted from the binary to detect vulnerable symbols.

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
			die("govulncheck: %v", err)
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
	fmt.Println(strings.Repeat("-", lineLength))
	for _, vg := range ci.VulnGroups {
		// All the vulns in vg have the same PkgPath, ModPath and OSV.
		// All have a non-zero CallSink.
		v0 := vg[0]
		fmt.Printf(`
%s
%s
`, v0.OSV.ID, v0.OSV.Details)
		if *verboseFlag {
			writeCallStacksVerbose(vg, ci)
		} else {
			writeCallStacksDefault(vg, ci)
		}
		fmt.Println()
		found := v0.PkgPath
		if v := ci.ModuleVersions[v0.ModPath]; v != "" {
			found = packageVersionString(v0.PkgPath, v[1:])
		}
		fmt.Printf("Found in:  %v\n", found)
		if fixed := govulncheck.LatestFixed(v0.OSV.Affected); fixed != "" {
			fmt.Printf("Fixed in:  %s\n", packageVersionString(v0.PkgPath, fixed))
		}
		fmt.Printf("More info: https://pkg.go.dev/vuln/%s\n", v0.OSV.ID)
		fmt.Println()
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

func writeCallStacksDefault(vg []*vulncheck.Vuln, ci *govulncheck.CallInfo) {
	var summaries []string
	for _, v := range vg {
		if css := ci.CallStacks[v]; len(css) > 0 {
			if sum := govulncheck.SummarizeCallStack(css[0], ci.TopPackages, v.PkgPath); sum != "" {
				summaries = append(summaries, sum)
			}
		}
	}
	if len(summaries) > 0 {
		sort.Strings(summaries)
		summaries = compact(summaries)
		fmt.Println("Call stacks in your code:")
		for _, s := range summaries {
			fmt.Println("", s)
		}
	}
}

func writeCallStacksVerbose(vg []*vulncheck.Vuln, ci *govulncheck.CallInfo) {
	// Display one full call stack for each vuln.
	fmt.Println("Call stacks in your code:")
	nMore := 0
	i := 1
	for _, v := range vg {
		css := ci.CallStacks[v]
		if len(css) == 0 {
			continue
		}
		fmt.Printf("    #%d: for function %s\n", i, v.Symbol)
		writeCallStack(css[0])
		fmt.Println()
		i++
		nMore += len(css) - 1
	}
	if nMore > 0 {
		fmt.Printf("    There are %d more call stacks available.\n", nMore)
		fmt.Printf("To     see all of them, pass the -json or -html flags.\n")
	}
}

func writeCallStack(cs vulncheck.CallStack) {
	for _, e := range cs {
		fmt.Printf("        %s\n", govulncheck.FuncName(e.Function))
		if e.Call != nil && e.Call.Pos != nil {
			fmt.Printf("            %s\n", e.Call.Pos.String())
		}
	}
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
