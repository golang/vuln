// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Govulncheck reports known vulnerabilities that affect Go code. It uses static
analysis of source code or a binary's symbol table to narrow down reports to
only those that could affect the application.

By default, govulncheck makes requests to the Go vulnerability database at
https://vuln.go.dev. Requests to the vulnerability database contain only module
paths, not code or other properties of your program. See
https://vuln.go.dev/privacy.html for more. Set the GOVULNDB environment
variable to specify a different database, which must implement the
specification at https://go.dev/security/vuln/database.

Govulncheck looks for vulnerabilities in Go programs using a specific build
configuration. For analyzing source code, that configuration is the operating
system, architecture, and Go version specified by GOOS, GOARCH, and the “go”
command found on the PATH. For binaries, the build configuration is the one
used to build the binary. Note that different build configurations may have
different known vulnerabilities. For example, a dependency with a
Windows-specific vulnerability will not be reported for a Linux build.

Govulncheck must be built with Go version 1.18 or later.

# Usage

To analyze source code, run govulncheck from the module directory, using the
same package path syntax that the go command uses:

	$ cd my-module
	$ govulncheck ./...

If no vulnerabilities are found, govulncheck will display a short message. If
there are vulnerabilities, each is displayed briefly, with a summary of a call
stack.

The call stack summary shows in brief how the package calls a vulnerable
function. For example, it might say

	main.go:[line]:[column]: mypackage.main calls golang.org/x/text/language.Parse

For a more detailed call path that resembles Go panic stack traces, use the -v flag.

To control which files are processed, use the -tags flag to provide a
comma-separated list of build tags, and the -test flag to indicate that test
files should be included.

To run govulncheck on a compiled binary, pass it the path to the binary file:

	$ govulncheck $HOME/go/bin/my-go-program

Govulncheck uses the binary's symbol information to find mentions of vulnerable
functions. Its output omits call stacks, which require source code analysis.

Govulncheck exits successfully (exit code 0) if there are no vulnerabilities,
and exits unsuccessfully if there are.

# Flags

A few flags control govulncheck's behavior.

The -v flag causes govulncheck to output more information about call stacks
when run on source. It has no effect when run on a binary.

The -json flag causes govulncheck to print its output as a JSON object
corresponding to the type [golang.org/x/vuln/vulncheck.Result].

The -tags flag accepts a comma-separated list of build tags to control which
files should be included in loaded packages for source analysis.

The -test flag causes govulncheck to include test files in the source analysis.

# Limitations

Govulncheck uses [golang.org/x/vuln/vulncheck], which has these limitations:

  - Govulncheck analyzes function pointer and interface calls conservatively,
    which may result in false positives or inaccurate call stacks in some cases.
  - Calls to functions made using package reflect are not visible to static
    analysis. Vulnerable code reachable only through those calls will not be
    reported.
  - Because Go binaries do not contain detailed call information, vulncheck
    cannot show the call graphs for detected vulnerabilities. It may also
    report false positives for code that is in the binary but unreachable.
  - Govulncheck does not report vulnerabilities in
    vendored packages for binaries.
  - There is no support for silencing vulnerability findings.
  - Govulncheck only reads binaries compiled with Go 1.18 and later.

# Feedback

Govulncheck is an experimental tool under active development. To share
feedback, see https://go.dev/security/vuln#feedback.
*/
package main
