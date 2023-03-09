# Go Vulnerability Database

## Accessing the database

The Go vulnerability database is rooted at
`https://vuln.go.dev` and provides data as JSON.

Do not rely on the contents of the x/vulndb repository. The YAML files in that
repository are maintained using an internal format that is subject to change
without warning.

The endpoints the table below are supported. For each path:

- $base is the path portion of a Go vulnerability database URL (`https://vuln.go.dev`).
- $module is a module path
- $vuln is a Go vulnerabilitiy ID (for example, `GO-2021-1234`)

| Path                | Description                                                                                                                               |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| $base/index.json    | List of module paths in the database mapped to its last modified timestamp ([link](https://vuln.go.dev/index.json)). |
| $base/$module.json  | List of vulnerability entries for that module ([example](https://vuln.go.dev/golang.org/x/crypto.json)).             |
| $base/ID/index.json | List of all the vulnerability entries in the database                                                                                     |
| $base/ID/$vuln.json | An individual Go vulnerability report                                                                                                     |

Note that these paths and format are provisional and likely to change until an
approved proposal.
