// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"fmt"
	"io"
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

	err = doGovulncheck(cfg, w)
	if cfg.json && err == ErrVulnerabilitiesFound {
		return nil
	}
	return err
}
