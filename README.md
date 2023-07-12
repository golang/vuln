# Go Vulnerability Management

[![Go Reference](https://pkg.go.dev/badge/golang.org/x/vuln.svg)](https://pkg.go.dev/golang.org/x/vuln)

Go's support for vulnerability management includes tooling for analyzing your
codebase and binaries to surface known vulnerabilities in your dependencies.
This tooling is backed by the Go vulnerability database, which is curated by
the Go security team. Go’s tooling reduces noise in your results by only
surfacing vulnerabilities in functions that your code is actually calling.

You can install the latest version of govulncheck using
[go install](https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies)

```
go install golang.org/x/vuln/cmd/govulncheck@latest
```

Then, run govulncheck inside your module:
```
govulncheck ./...
```

See [the govulncheck tutorial](https://go.dev/doc/tutorial/govulncheck) to get
started, and [https://go.dev/security/vuln](https://go.dev/security/vuln) for
more information about Go's support for vulnerability management. The API
documentation can be found at
[https://pkg.go.dev/golang.org/x/vuln/scan](https://pkg.go.dev/golang.org/x/vuln/scan).

## Privacy Policy

The privacy policy for `govulncheck` can be found at
[https://vuln.go.dev/privacy](https://vuln.go.dev/privacy).

## License

Unless otherwise noted, the Go source files are distributed under the BSD-style
license found in the LICENSE file.

Database entries available at https://vuln.go.dev are distributed under the
terms of the [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) license.
