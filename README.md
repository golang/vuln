# Go Vulnerability Database

[![Go Reference](https://pkg.go.dev/badge/golang.org/x/vuln.svg)](https://pkg.go.dev/golang.org/x/vuln)

This repository contains code for hosting the Go Vulnerability Database. The
actual reports can be found at [x/vulndb](https://go.googlesource.com/vulndb).

Neither the code, nor the data, nor the existence of this repository is to be
considered stable. See the
[Draft Design](https://golang.org/design/draft-vulndb) for details on this
project.

## Accessing the database

The Go vulnerability database is rooted at
`https://storage.googleapis.com/go-vulndb` and provides data as JSON. We
recommend using
[client.Client](https://pkg.go.dev/golang.org/x/vuln/client#Client) to read
data from the Go vulnerability database.

Do not rely on the contents of the x/vulndb repository. The YAML files in that
repository are maintained using an internal format that is subject to change
without warning.

The endpoints the table below are supported. For each path:

- $base is the path portion of a Go vulnerability database URL (`https://storage.googleapis.com/go-vulndb`).
- $module is a module path
- $vuln is a Go vulnerabilitiy ID (for example, `GO-2021-1234`)

| Path                | Description                                                                                                                               |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| $base/index.json    | List of module paths in the database mapped to its last modified timestamp ([link](https://storage.googleapis.com/go-vulndb/index.json)). |
| $base/$module.json  | List of vulnerability entries for that module ([example](https://storage.googleapis.com/go-vulndb/golang.org/x/crypto.json)).             |
| $base/ID/index.json | List of all the vulnerability entries in the database                                                                                     |
| $base/ID/$vuln.json | An individual Go vulnerability report                                                                                                     |

Note that these paths and format are provisional and likely to change until an
approved proposal.

## Packages

Some of these packages can probably be coalesced, but for now are easier to work
on in a more segmented fashion.

- `osv` provides a package for generating OSV-style JSON vulnerability entries
  from a `report.Report`
- `client` contains a client for accessing HTTP/fs based vulnerability
  databases, as well as a minimal caching implementation
- `cmd/dbdiff` provides a tool for comparing two different versions of the
  vulnerability database
- `cmd/gendb` provides a tool for converting YAML reports into JSON database
- `cmd/linter` provides a tool for linting individual reports
- `cmd/report2cve` provides a tool for converting YAML reports into JSON CVEs

## License

Unless otherwise noted, the Go source files are distributed under
the BSD-style license found in the LICENSE file.

Database entries available at https://storage.googleapis.com/go-vulndb/ are
distributed under the terms of the
[CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) license.
