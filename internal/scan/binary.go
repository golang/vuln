// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package scan

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"golang.org/x/vuln/internal/buildinfo"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/vulncheck"
)

// runBinary detects presence of vulnerable symbols in an executable.
func runBinary(ctx context.Context, handler govulncheck.Handler, cfg *config, client *client.Client) (err error) {
	defer derrors.Wrap(&err, "govulncheck")

	exe, err := os.Open(cfg.patterns[0])
	if err != nil {
		return err
	}
	defer exe.Close()

	bin, err := createBin(exe)
	if err != nil {
		return err
	}

	p := &govulncheck.Progress{Message: binaryProgressMessage}
	if err := handler.Progress(p); err != nil {
		return err
	}
	return vulncheck.Binary(ctx, handler, bin, &cfg.Config, client)
}

func createBin(exe io.ReaderAt) (*vulncheck.Bin, error) {
	mods, packageSymbols, bi, err := buildinfo.ExtractPackagesAndSymbols(exe)
	if err != nil {
		return nil, fmt.Errorf("could not parse provided binary: %v", err)
	}
	return &vulncheck.Bin{
		Modules:    mods,
		PkgSymbols: packageSymbols,
		GoVersion:  bi.GoVersion,
		GOOS:       findSetting("GOOS", bi),
		GOARCH:     findSetting("GOARCH", bi),
	}, nil
}

// findSetting returns value of setting from bi if present.
// Otherwise, returns "".
func findSetting(setting string, bi *debug.BuildInfo) string {
	for _, s := range bi.Settings {
		if s.Key == setting {
			return s.Value
		}
	}
	return ""
}
