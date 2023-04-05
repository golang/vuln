// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"encoding/json"

	"io"
)

type jsonHandler struct {
	enc *json.Encoder
}

// NewJSONHandler returns a handler that writes govulncheck output as json.
func NewJSONHandler(w io.Writer) Handler {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return &jsonHandler{enc: enc}
}

// Config does not do anything in JSON mode.
func (o *jsonHandler) Config(config *Config) error {
	return o.enc.Encode(Message{Config: config})
}

// Progress does not do anything in JSON mode.
func (o *jsonHandler) Progress(progress *Progress) error {
	return o.enc.Encode(Message{Progress: progress})
}

// Vulnerability gathers vulnerabilities to be written.
func (o *jsonHandler) Vulnerability(vuln *Vuln) error {
	return o.enc.Encode(Message{Vulnerability: vuln})
}
