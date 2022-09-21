// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build testmode

package main

import "flag"

func init() {
	flag.StringVar(&dirFlag, "dir", "", "directory to use for loading source files")
	flag.BoolVar(&summaryJSONFlag, "summary-json", false, "output govulnchecklib.Summary JSON")
}
