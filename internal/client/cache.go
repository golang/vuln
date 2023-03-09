// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"time"

	"golang.org/x/vuln/osv"
)

// A Cache caches vuln DB entries for modules.
// A single cache can support multiple DBs from different sources, each with a
// different name.
type Cache interface {
	// ReadIndex returns the index for the given DB along with the time it was
	// last read from the source.
	ReadIndex(dbName string) (DBIndex, time.Time, error)

	// WriteIndex stores in the index and associated time for the given DB.
	WriteIndex(dbName string, index DBIndex, t time.Time) error

	// ReadEntries returns the entries for modulePath in the named DB.
	ReadEntries(dbName, modulePath string) ([]*osv.Entry, error)

	// WriteEntries stores the entries associated with modulePath in the named
	// DB.
	WriteEntries(dbName, modulePath string, entries []*osv.Entry) error
}
