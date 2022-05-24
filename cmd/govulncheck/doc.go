// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

/*
Command govulncheck reports known vulnerabilities that affect Go code. It uses
static analysis or a binary's symbol table to narrow down reports to only those
that potentially affect the application. For more information about the API
behind govulncheck, see https://go.dev/security/vulncheck.


By default, govulncheck uses the Go vulnerability database at
https://vuln.go.dev. Set the GOVULNDB environment variable to specify a different database.
The database must follow the specification at https://go.dev/security/vulndb.

Govulncheck requires Go version 1.18 or higher to run.

WARNING: govulncheck is still EXPERIMENTAL and neither its output or the vulnerability
database should be relied on to be stable or comprehensive.

Usage

To analyze source code, run govulncheck from the module directory, using the
same package path syntax that the go command uses:

	$ cd my-module
	$ govulncheck ./...

If no vulnerabilities are found, govulncheck produces no output and exits with code 0.
If there are vulnerabilities, each is displayed briefly, with a summary of a call stack,
and govulncheck exits with code 3.

The call stack summary shows in brief how the package calls a vulnerable function.
For example, it might say

	mypackage.main calls golang.org/x/text/language.Parse

For more detailed call path that resemble Go panic stack traces, use the -v flag.

To control which files are processed, use the -tags flag to provide a
comma-separate list of build tags, and the -tests flag to indicate that test
files should be included.

To run govulncheck on a compiled binary, pass it the path to the binary file:

	$ govulncheck $HOME/go/bin/my-go-program

Govulncheck uses the binary's symbol information to find mentions of vulnerable functions.
Its output and exit codes are as described above, except that without source it cannot
produce call stacks.

Other Modes

A few flags control govulncheck's output. Regardless of output, govulncheck
exits with code 0 if there are no vulnerabilities and 3 if there are.

The -v flag outputs more information about call stacks when run on source. It has
no effect when run on a binary.

The -html flag outputs HTML instead of plain text.

The -json flag outputs a JSON object with vulnerability information. The output
corresponds to the type golang.org/x/vuln/vulncheck.Result.

Weaknesses

Govulncheck uses static analysis, which is inherently imprecise. If govulncheck
identifies a sequence of calls in your program that leads to a vulnerable
function, that path may never be executed because of conditions in the code, or
it may call the vulnerable function with harmless input.

The call graph analysis that govulncheck performs cannot find calls that use
Go's reflect or unsafe packages. It is possible for govulncheck to miss
vulnerabilities in programs that call functions in these unusual ways.
*/
package main
