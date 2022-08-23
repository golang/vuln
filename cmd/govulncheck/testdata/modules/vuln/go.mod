module golang.org/vuln

go 1.18

require (
	// This version has a vulnerability that is imported.
	github.com/tidwall/gjson v1.9.2
	// This version has a vulnerability that is called.
	golang.org/x/text v0.3.0
)

require (
	github.com/tidwall/match v1.1.0 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
)
