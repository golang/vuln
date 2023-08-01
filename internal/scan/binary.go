// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unicode"

	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/vulncheck"
)

// runBinary detects presence of vulnerable symbols in an executable.
func runBinary(ctx context.Context, handler govulncheck.Handler, cfg *config, client *client.Client) error {
	var exe *os.File
	exe, err := os.Open(cfg.patterns[0])
	if err != nil {
		return err
	}
	defer exe.Close()

	p := &govulncheck.Progress{Message: binaryProgressMessage}
	if err := handler.Progress(p); err != nil {
		return err
	}
	vr, err := vulncheck.Binary(ctx, exe, &cfg.Config, client)
	if err != nil {
		return fmt.Errorf("govulncheck: %v", err)
	}
	callstacks := binaryCallstacks(vr)
	return emitResult(handler, vr, callstacks)
}

func binaryCallstacks(vr *vulncheck.Result) map[*vulncheck.Vuln]vulncheck.CallStack {
	callstacks := map[*vulncheck.Vuln]vulncheck.CallStack{}
	for _, vv := range uniqueVulns(vr.Vulns) {
		f := &vulncheck.FuncNode{Package: vv.ImportSink, Name: vv.Symbol}
		parts := strings.Split(vv.Symbol, ".")
		if len(parts) != 1 {
			f.RecvType = parts[0]
			f.Name = parts[1]
		}
		callstacks[vv] = vulncheck.CallStack{vulncheck.StackEntry{Function: f}}
	}
	return callstacks
}

// uniqueVulns does for binary mode what uniqueCallStack does for source mode.
// It tries not to report redundant symbols. Since there are no call stacks in
// binary mode, the following approximate approach is used. Do not report unexported
// symbols for a <vulnID, pkg, module> triple if there are some exported symbols.
// Otherwise, report all unexported symbols to avoid not reporting anything.
func uniqueVulns(vulns []*vulncheck.Vuln) []*vulncheck.Vuln {
	type key struct {
		id  string
		pkg string
		mod string
	}
	hasExported := make(map[key]bool)
	for _, v := range vulns {
		if isExported(v.Symbol) {
			k := key{id: v.OSV.ID, pkg: v.ImportSink.PkgPath, mod: v.ImportSink.Module.Path}
			hasExported[k] = true
		}
	}

	var uniques []*vulncheck.Vuln
	for _, v := range vulns {
		k := key{id: v.OSV.ID, pkg: v.ImportSink.PkgPath, mod: v.ImportSink.Module.Path}
		if isExported(v.Symbol) || !hasExported[k] {
			uniques = append(uniques, v)
		}
	}
	return uniques
}

// isExported checks if the symbol is exported. Assumes that the
// symbol is of the form "identifier" or "identifier1.identifier2".
func isExported(symbol string) bool {
	parts := strings.Split(symbol, ".")
	if len(parts) == 1 {
		return unicode.IsUpper(rune(symbol[0]))
	}
	return unicode.IsUpper(rune(parts[1][0]))
}
