// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"encoding/json"
	"fmt"

	"io"

	"golang.org/x/vuln/client"
)

type jsonOutput struct {
	to io.Writer
}

func (o *jsonOutput) intro(ctx context.Context, dbClient client.Client, dbs []string, source bool) {}

func (o *jsonOutput) result(r *Result, verbose, source bool) error {
	b, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		return err
	}
	o.to.Write(b)
	fmt.Fprintln(o.to)
	return nil
}

func (o *jsonOutput) progress(msg string) {}
