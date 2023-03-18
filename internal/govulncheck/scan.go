// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/result"
	"golang.org/x/vuln/internal/vulncheck"
)

func Main(ctx context.Context, args []string, w io.Writer) (err error) {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}
	if !cfg.sourceAnalysis {
		if cfg.test {
			return fmt.Errorf("govulncheck: the -test flag is invalid for binaries")
		}
		if cfg.tags != nil {
			return fmt.Errorf("govulncheck: the -tags flag is invalid for binaries")
		}
	}

	var output Handler
	switch {
	case cfg.json:
		output = NewJSONHandler(w)
	default:
		output = NewTextHandler(w, cfg.verbose, cfg.sourceAnalysis)
	}
	err = doGovulncheck(cfg, output)
	if cfg.json && err == ErrVulnerabilitiesFound {
		return nil
	}
	return err
}

type config struct {
	patterns       []string
	sourceAnalysis bool
	db             string
	json           bool
	dir            string
	verbose        bool
	tags           []string
	test           bool
}

const (
	envGOVULNDB = "GOVULNDB"
	vulndbHost  = "https://vuln.go.dev"
)

var (
	ErrMissingArgPatterns   = errors.New("missing any pattern args")
	ErrVulnerabilitiesFound = errors.New("vulnerabilities found")
)

func parseFlags(args []string) (*config, error) {
	cfg := &config{}
	var tagsFlag buildutil.TagsFlag
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.BoolVar(&cfg.json, "json", false, "output JSON")
	flags.BoolVar(&cfg.verbose, "v", false, "print a full call stack for each vulnerability")
	flags.BoolVar(&cfg.test, "test", false, "analyze test files. Only valid for source code.")
	flags.Var(&tagsFlag, "tags", "comma-separated `list` of build tags")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), `usage:
	govulncheck [flags] package...
	govulncheck [flags] binary

`)
		flags.PrintDefaults()
		fmt.Fprintf(flags.Output(), "\n%s\n", detailsMessage)
	}
	addTestFlags(flags, cfg)
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	cfg.patterns = flags.Args()
	if len(cfg.patterns) == 0 {
		flags.Usage()
		return nil, ErrMissingArgPatterns
	}
	cfg.sourceAnalysis = true
	if len(cfg.patterns) == 1 && isFile(cfg.patterns[0]) {
		cfg.sourceAnalysis = false
	}
	cfg.tags = tagsFlag
	cfg.db = vulndbHost
	if db := os.Getenv(envGOVULNDB); db != "" {
		cfg.db = db
	}
	return cfg, nil
}

// doGovulncheck performs main govulncheck functionality and exits the
// program upon success with an appropriate exit status. Otherwise,
// returns an error.
func doGovulncheck(c *config, output Handler) error {
	ctx := context.Background()
	dir := filepath.FromSlash(c.dir)

	cache, err := DefaultCache()
	if err != nil {
		return err
	}
	dbClient, err := client.NewClient(c.db, client.Options{
		HTTPCache: cache,
	})
	if err != nil {
		return err
	}

	// Write the introductory message to the user.
	if err := output.Preamble(newPreamble(ctx, dbClient, c.db, c.sourceAnalysis)); err != nil {
		return err
	}

	// config GoVersion is "", which means use current
	// Go version at path.
	cfg := &Config{Client: dbClient}
	var res *result.Result
	if c.sourceAnalysis {
		res, err = sourceAnalysis(ctx, output, c, cfg, dir)
	} else {
		res, err = binaryAnalysis(ctx, output, c, cfg)
	}
	if err != nil {
		return err
	}

	// For each vulnerability, queue it to be written to the output.
	for _, v := range res.Vulns {
		if err := output.Vulnerability(v); err != nil {
			return err
		}
	}
	if err := output.Flush(); err != nil {
		return err
	}
	if len(res.Vulns) > 0 {
		return ErrVulnerabilitiesFound
	}
	return nil
}

func sourceAnalysis(ctx context.Context, output Handler, c *config, cfg *Config, dir string) (*result.Result, error) {
	var pkgs []*vulncheck.Package
	pkgs, err := loadPackages(c, dir)
	if err != nil {
		// Try to provide a meaningful and actionable error message.
		if !fileExists(filepath.Join(dir, "go.mod")) {
			return nil, fmt.Errorf("govulncheck: %v", errNoGoMod)
		}
		if isGoVersionMismatchError(err) {
			return nil, fmt.Errorf("govulncheck: %v\n\n%v", errGoVersionMismatch, err)
		}
		return nil, err
	}
	if err := output.Progress(sourceProgressMessage(pkgs)); err != nil {
		return nil, err
	}
	return Source(ctx, cfg, pkgs)
}

func binaryAnalysis(ctx context.Context, output Handler, c *config, cfg *Config) (*result.Result, error) {
	var f *os.File
	f, err := os.Open(c.patterns[0])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := output.Progress(binaryProgressMessage); err != nil {
		return nil, err
	}
	return Binary(ctx, cfg, f)
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}

// loadPackages loads the packages matching patterns at dir using build tags
// provided by tagsFlag. Uses load mode needed for vulncheck analysis. If the
// packages contain errors, a packageError is returned containing a list of
// the errors, along with the packages themselves.
func loadPackages(c *config, dir string) ([]*vulncheck.Package, error) {
	var buildFlags []string
	if c.tags != nil {
		buildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(c.tags, ","))}
	}

	cfg := &packages.Config{Dir: dir, Tests: c.test}
	cfg.Mode |= packages.NeedName | packages.NeedImports | packages.NeedTypes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule
	cfg.BuildFlags = buildFlags

	pkgs, err := packages.Load(cfg, c.patterns...)
	vpkgs := vulncheck.Convert(pkgs)
	if err != nil {
		return nil, err
	}
	var perrs []packages.Error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		perrs = append(perrs, p.Errors...)
	})
	if len(perrs) > 0 {
		err = &packageError{perrs}
	}
	return vpkgs, err
}

func newPreamble(ctx context.Context, dbClient client.Client, db string, source bool) *result.Preamble {
	preamble := result.Preamble{
		DBsPhrase: db,
	}
	// The Go version is only relevant for source analysis, so omit it for
	// binary mode.
	if source {
		if v, err := internal.GoEnv("GOVERSION"); err == nil {
			preamble.GoPhrase = fmt.Sprintf("%s and ", v)
		}
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		preamble.GovulncheckVersion = fmt.Sprintf("@%s", govulncheckVersion(bi))
	}
	if lmod, err := dbClient.LastModifiedTime(ctx); err == nil {
		preamble.DBLastModifiedPhrase = fmt.Sprintf(" (last modified %s )", lmod.Format(time.RFC822))
	}
	return &preamble
}
