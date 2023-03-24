// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

// Handler handles messages to be presented in a vulnerability scan output
// stream.
type Handler interface {
	// Flush writes any output the handler is buffering.
	Flush() error

	// Vulnerability adds a vulnerability to be printed to the output.
	Vulnerability(vuln *Vuln) error

	// Preamble communicates introductory message to the user.
	Preamble(preamble *Preamble) error

	// Progress is called to display a progress message.
	Progress(msg string) error
}
