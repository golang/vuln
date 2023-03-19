// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"encoding/json"

	"io"

	"golang.org/x/vuln/internal/result"
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

// HandleJSON reads the json from the supplied stream and hands the decoded
// output to the handler.
func HandleJSON(from io.Reader, to Handler) error {
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := result.Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		// dispatch the message
		//TODO: should we verify only one field was set?
		var err error
		if msg.Preamble != nil {
			err = to.Preamble(msg.Preamble)
		}
		if msg.Vulnerability != nil {
			err = to.Vulnerability(msg.Vulnerability)
		}
		if msg.Progress != "" {
			err = to.Progress(msg.Progress)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Flush writes all vulnerabilities in JSON format.
func (o *jsonHandler) Flush() error {
	return nil
}

// Vulnerability gathers vulnerabilities to be written.
func (o *jsonHandler) Vulnerability(vuln *result.Vuln) error {
	return o.enc.Encode(result.Message{Vulnerability: vuln})
}

// Preamble does not do anything in JSON mode.
func (o *jsonHandler) Preamble(preamble *result.Preamble) error {
	return o.enc.Encode(result.Message{Preamble: preamble})
}

// Progress does not do anything in JSON mode.
func (o *jsonHandler) Progress(msg string) error {
	return o.enc.Encode(result.Message{Progress: msg})
}
