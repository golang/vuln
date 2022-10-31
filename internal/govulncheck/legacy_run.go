// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/vulncheck"
)

// LegacyRun is the main function for the govulncheck command line tool.
//
// TODO: inline into cmd/govulncheck. This will effectively remove the
// need for having additional (Legacy)Config.
func LegacyRun(ctx context.Context, lcfg LegacyConfig) (*Result, error) {
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

	format := lcfg.OutputType
	if format == OutputTypeText || format == OutputTypeVerbose {
		fmt.Println(introMessage)
	}

	cfg := &Config{Client: dbClient, GoVersion: lcfg.GoVersion}
	var res *Result
	switch lcfg.AnalysisType {
	case AnalysisTypeBinary:
		f, err := os.Open(lcfg.Patterns[0])
		if err != nil {
			return nil, err
		}
		defer f.Close()
		res, err = Binary(ctx, cfg, f)
	case AnalysisTypeSource:
		pkgs, err := loadPackages(lcfg)
		if err != nil {
			// Try to provide a meaningful and actionable error message.
			if !fileExists(filepath.Join(lcfg.SourceLoadConfig.Dir, "go.mod")) {
				return nil, ErrNoGoMod
			}
			if !fileExists(filepath.Join(lcfg.SourceLoadConfig.Dir, "go.sum")) {
				return nil, ErrNoGoSum
			}
			if isGoVersionMismatchError(err) {
				return nil, fmt.Errorf("%v\n\n%v", ErrGoVersionMismatch, err)
			}
			return nil, err
		}
		res, err = Source(ctx, cfg, pkgs)
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAnalysisType, lcfg.AnalysisType)
	}
	if err != nil {
		return nil, err
	}

	switch lcfg.OutputType {
	case OutputTypeJSON:
		// Following golang.org/x/tools/go/analysis/singlechecker,
		// return 0 exit code in -json mode.
		if err := printJSON(res); err != nil {
			return nil, err
		}
		return res, nil
	case OutputTypeText, OutputTypeVerbose:
		source := lcfg.AnalysisType == AnalysisTypeSource
		printText(res, lcfg.OutputType == OutputTypeVerbose, source)
		// Return error if some vulnerabilities are actually called.
		if source {
			for _, v := range res.Vulns {
				if v.IsCalled() {
					return nil, ErrContainsVulnerabilties
				}
			}
		} else if len(res.Vulns) > 0 {
			return nil, ErrContainsVulnerabilties
		}
		return res, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidOutputType, lcfg.OutputType)
	}
}

// A PackageError contains errors from loading a set of packages.
type PackageError struct {
	Errors []packages.Error
}

func (e *PackageError) Error() string {
	var b strings.Builder
	fmt.Fprintln(&b, "Packages contain errors:")
	for _, e := range e.Errors {
		fmt.Fprintln(&b, e)
	}
	return b.String()
}

// loadPackages loads the packages matching patterns using cfg, after setting
// the cfg mode flags that vulncheck needs for analysis.
// If the packages contain errors, a PackageError is returned containing a list of the errors,
// along with the packages themselves.
func loadPackages(cfg LegacyConfig) ([]*vulncheck.Package, error) {
	patterns := cfg.Patterns
	cfg.SourceLoadConfig.Mode |= packages.NeedName | packages.NeedImports | packages.NeedTypes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule

	pkgs, err := packages.Load(cfg.SourceLoadConfig, patterns...)
	vpkgs := vulncheck.Convert(pkgs)
	if err != nil {
		return nil, err
	}
	var perrs []packages.Error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		perrs = append(perrs, p.Errors...)
	})
	if len(perrs) > 0 {
		err = &PackageError{perrs}
	}
	return vpkgs, err
}
