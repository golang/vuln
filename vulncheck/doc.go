// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package vulncheck detects uses of known vulnerabilities
in Go programs.

vulncheck identifies vulnerability uses in Go programs at the level of call
graph, package import graph, and module requires graph. For instance, vulncheck
identifies which vulnerable functions and methods are transitively called from
the program entry points. vulncheck also detects transitively imported packages
and required modules that contain known vulnerable functions and methods.

A broader overview of vulncheck can be found at
https://go.dev/security/vuln/vulncheck.

# Usage

The two main APIs of vulncheck, Source and Binary, allow vulnerability
detection in Go source code and binaries, respectively.

Source accepts a list of [Package] objects, which are a trimmed version of
[golang.org/x/tools/go/packages.Package] objects to reduce memory consumption.
Binary accepts a path to a Go binary file that must have been compiled with Go
1.18 or greater. Earlier versions omit the list of modules used by the binary,
which vulncheck needs to find vulnerabilities.

Both Source and Binary require information about known vulnerabilities in the
form of a vulnerability database, specifically a
[golang.org/x/vuln/client.Client]. The vulnerabilities are modeled using the
[golang.org/x/vuln/osv] format.

# Results

The results of vulncheck are slices of the call graph, package imports graph,
and module requires graph leading to the use of an identified vulnerability.
Parts of these graphs not related to any vulnerabilities are omitted.

# Vulnerability Witnesses

[CallStacks] and [ImportChains] APIs search the returned slices for
user-friendly representative call stacks and import chains.  Clients of
vulncheck can use these stacks and chains as a witness of a vulnerability use
during, for instance, security review.

# Limitations

Please see the [documented limitations].

[documented limitations]: https://go.dev/security/vulncheck#limitations.
*/
package vulncheck
