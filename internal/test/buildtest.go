// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/vuln/internal/testenv"
)

var unsupportedGoosGoarch = map[string]bool{
	"darwin/386": true,
	"darwin/arm": true,
}

// GoBuild runs "go build" on dir using the additional environment variables in
// envVarVals, which should be an alternating list of variables and values.
// It returns the path to the resulting binary, and a function
// to call when finished with the binary.
func GoBuild(t *testing.T, dir, tags string, strip bool, envVarVals ...string) (binaryPath string, cleanup func()) {
	testenv.NeedsGoBuild(t)

	if len(envVarVals)%2 != 0 {
		t.Fatal("last args should be alternating variables and values")
	}
	var env []string
	if len(envVarVals) > 0 {
		env = os.Environ()
		for i := 0; i < len(envVarVals); i += 2 {
			env = append(env, fmt.Sprintf("%s=%s", envVarVals[i], envVarVals[i+1]))
		}
	}

	gg := lookupEnv("GOOS", env, runtime.GOOS) + "/" + lookupEnv("GOARCH", env, runtime.GOARCH)
	if unsupportedGoosGoarch[gg] {
		t.Skipf("skipping unsupported GOOS/GOARCH pair %s", gg)
	}

	tmpDir, err := os.MkdirTemp("", "buildtest")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	binaryPath = filepath.Join(tmpDir, filepath.Base(abs))
	var exeSuffix string
	if runtime.GOOS == "windows" {
		exeSuffix = ".exe"
	}
	// Make sure we use the same version of go that is running this test.
	goCommandPath := filepath.Join(runtime.GOROOT(), "bin", "go"+exeSuffix)
	if _, err := os.Stat(goCommandPath); err != nil {
		t.Fatal(err)
	}
	args := []string{"build", "-o", binaryPath + exeSuffix}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	if strip {
		args = append(args, "-ldflags", "-s -w")
	}
	cmd := exec.Command(goCommandPath, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return binaryPath + exeSuffix, func() { os.RemoveAll(tmpDir) }
}

// lookEnv looks for name in env, a list of "VAR=VALUE" strings. It returns
// the value if name is found, and defaultValue if it is not.
func lookupEnv(name string, env []string, defaultValue string) string {
	for _, vv := range env {
		i := strings.IndexByte(vv, '=')
		if i < 0 {
			// malformed env entry; just ignore it
			continue
		}
		if name == vv[:i] {
			return vv[i+1:]
		}
	}
	return defaultValue
}
