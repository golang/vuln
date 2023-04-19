// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package buildinfo

// Code in this package is dervied from src/cmd/go/internal/version/version.go
// and cmd/go/internal/version/exe.go.

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"net/url"
	"runtime/debug"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/vulncheck/internal/gosym"
)

func debugModulesToPackagesModules(debugModules []*debug.Module) []*packages.Module {
	packagesModules := make([]*packages.Module, len(debugModules))
	for i, mod := range debugModules {
		packagesModules[i] = &packages.Module{
			Path:    mod.Path,
			Version: mod.Version,
		}
		if mod.Replace != nil {
			packagesModules[i].Replace = &packages.Module{
				Path:    mod.Replace.Path,
				Version: mod.Replace.Version,
			}
		}
	}
	return packagesModules
}

// ExtractPackagesAndSymbols extracts symbols, packages, modules from
// bin as well as bin's metadata.
//
// If the symbol table is not available, such as in the case of stripped
// binaries, returns module and binary info but without the symbol info.
func ExtractPackagesAndSymbols(bin io.ReaderAt) ([]*packages.Module, map[string][]string, *debug.BuildInfo, error) {
	bi, err := buildinfo.Read(bin)
	if err != nil {
		return nil, nil, nil, err
	}

	funcSymName := gosym.FuncSymName(bi.GoVersion)
	if funcSymName == "" {
		return nil, nil, nil, fmt.Errorf("binary built using unsupported Go version: %q", bi.GoVersion)
	}

	x, err := openExe(bin)
	if err != nil {
		return nil, nil, nil, err
	}

	value, base, r, err := x.SymbolInfo(funcSymName)
	if err != nil {
		if errors.Is(err, ErrNoSymbols) {
			// bin is stripped, so return just module info and metadata.
			return debugModulesToPackagesModules(bi.Deps), nil, bi, nil
		}
		return nil, nil, nil, fmt.Errorf("reading %v: %v", funcSymName, err)
	}

	pclntab, textOffset := x.PCLNTab()
	if pclntab == nil {
		// TODO(https://go.dev/issue/59731): if we have build information, but
		// not PCLN table, we should be able to fall back to much higher
		// granularity vulnerability checking.
		return nil, nil, nil, errors.New("unable to load the PCLN table")
	}
	lineTab := gosym.NewLineTable(pclntab, textOffset)
	if lineTab == nil {
		return nil, nil, nil, errors.New("invalid line table")
	}
	tab, err := gosym.NewTable(nil, lineTab)
	if err != nil {
		return nil, nil, nil, err
	}

	type pkgSymbol struct {
		pkg string
		sym string
	}
	pkgSyms := make(map[pkgSymbol]bool)
	for _, f := range tab.Funcs {
		if f.Func == nil {
			continue
		}
		pkgName, symName, err := parseName(f.Func.Sym)
		if err != nil {
			return nil, nil, nil, err
		}
		pkgSyms[pkgSymbol{pkgName, symName}] = true

		// Collect symbols that were inlined in f.
		it, err := lineTab.InlineTree(&f, value, base, r)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("InlineTree: %v", err)
		}
		for _, ic := range it {
			pkgName, symName, err := parseName(&gosym.Sym{Name: ic.Name})
			if err != nil {
				return nil, nil, nil, err
			}
			pkgSyms[pkgSymbol{pkgName, symName}] = true
		}
	}

	packageSymbols := make(map[string][]string)
	for p := range pkgSyms {
		packageSymbols[p.pkg] = append(packageSymbols[p.pkg], p.sym)
	}
	// Sort symbols per pkg for deterministic results.
	for _, syms := range packageSymbols {
		sort.Strings(syms)
	}

	return debugModulesToPackagesModules(bi.Deps), packageSymbols, bi, nil
}

func parseName(s *gosym.Sym) (pkg, sym string, err error) {
	symName := s.BaseName()
	if r := s.ReceiverName(); r != "" {
		if strings.HasPrefix(r, "(*") {
			r = strings.Trim(r, "(*)")
		}
		symName = fmt.Sprintf("%s.%s", r, symName)
	}

	pkgName := s.PackageName()
	if pkgName != "" {
		pkgName, err = url.PathUnescape(pkgName)
		if err != nil {
			return "", "", err
		}
	}
	return pkgName, symName, nil
}
