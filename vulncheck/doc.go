// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vulncheck detects uses of known vulnerabilities
// in Go programs. The two main APIs of vulncheck, Source
// and Binary, allow vulnerability detection in Go source
// code and binaries, respectively.
//
// vulncheck identifies vulnerability uses in Go programs
// at the level of call graph, package import graph, and module
// requires graph. For instance, vulncheck identifies which
// vulnerable functions and methods are transitively called
// from the program entry points. vulncheck also detects
// transitively imported packages and required modules that
// contain known vulnerable functions and methods.
//
// TODO(zpavlinovic): add a link to a more detailed overview of vulncheck
//
// Inputs
//
// Source accepts a list of vulncheck.Package objects, which
// are a trimmed version of packages.Package objects to reduce
// memory consumption. Binary accepts a path to a Go binary file
// that must have been compiled with Go 1.18 or greater. Otherwise,
// the list of modules used by the binary is unavailable and
// vulncheck hence might miss vulnerabilities present in the binary.
//
// Both Source and Binary require information about known
// vulnerabilities in the form of a vulnerability database
// https://golang.org/x/vuln/client#Client. The vulnerabilities
// are modeled using the shared https://golang.org/x/vuln/osv format.
//
// Results
//
// The result of vulncheck are slices of the call graph, package
// imports graph, and module requires graph leading to the use
// of an identified vulnerability. Parts of these graphs not
// related to any vulnerabilities are omitted.
//
// Vulnerability Witnesses
//
// CallStacks and ImportChains APIs search the returned slices
// for user-friendly representative call stacks and import chains.
// Clients of vulncheck can use these stacks and chains as a
// witness of a vulnerability use during, for instance, security
// review.
//
// Limitations
//
// Note that since statically constructing an exact call graph of
// a program is impossible, the produced call graph information
// is over-approximate: the results might contain call stacks not
// realizable in practice. On the other hand, vulncheck might
// miss some call graph edges in the presence of unsafe and reflect.
package vulncheck
