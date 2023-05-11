// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/vuln/internal/scan"
)

// Cmd represents an external govulncheck command being prepared or run,
// similar to exec.Cmd.
type Cmd struct {
	// Stdin specifies the standard input. If provided, it is expected to be
	// the output of govulncheck -json.
	Stdin io.Reader

	// Stdout specifies the standard output. If nil, Run connects os.Stdout.
	Stdout io.Writer

	// Stderr specifies the standard error. If nil, Run connects os.Stderr.
	Stderr io.Writer

	ctx     context.Context
	args    []string
	closers []io.Closer
	done    chan struct{}
	err     error
}

// Command returns the Cmd struct to execute govulncheck with the given
// arguments.
func Command(ctx context.Context, arg ...string) *Cmd {
	return &Cmd{
		ctx:  ctx,
		args: arg,
	}
}

// Start starts the specified command but does not wait for it to complete.
//
// After a successful call to Start the Wait method must be called in order to
// release associated system resources.
func (c *Cmd) Start() error {
	if c.done != nil {
		return errors.New("vuln: already started")
	}
	if c.Stdin == nil {
		c.Stdin = os.Stdin
	}
	if c.Stdout == nil {
		c.Stdout = os.Stdout
	}
	if c.Stderr == nil {
		c.Stderr = os.Stderr
	}
	c.done = make(chan struct{})
	go func() {
		defer func() {
			for _, cl := range c.closers {
				if err := cl.Close(); err != nil && c.err == nil {
					c.err = err
				}
			}
			c.closers = nil
			close(c.done)
		}()
		c.err = c.scan()
	}()
	return nil
}

// StdoutPipe returns a pipe that will be connected to the command's
// standard output when the command starts.
func (c *Cmd) StdoutPipe() io.ReadCloser {
	if c.Stdout != nil {
		panic("Stdout already set")
	}
	pr, pw := io.Pipe()
	c.Stdout = pw
	c.closers = append(c.closers, pw)
	return pr
}

// Wait waits for the command to exit. The command must have been started by
// Start.
//
// Wait releases any resources associated with the Cmd.
func (c *Cmd) Wait() error {
	if c.done == nil {
		return errors.New("vuln: start must be called before wait")
	}
	<-c.done
	return c.err
}

func (c *Cmd) scan() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	return scan.RunGovulncheck(c.ctx, c.Stdin, c.Stdout, c.Stderr, c.args)
}
