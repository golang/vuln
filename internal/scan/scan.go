// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"context"
	"errors"
	"io"
	"os"
)

// Cmd represents an external govulncheck command being prepared or run,
// similar to exec.Cmd.
type Cmd struct {
	// Stdout specifies the standard output. If nil, Run connects os.Stdout.
	Stdout io.Writer

	ctx     context.Context
	args    []string
	closers []io.Closer
	done    chan struct{}
	err     error
}

// Command is the equivalent of exec.Command
//
// Command returns the Cmd struct to execute govulncheck with the given
// arguments. It does not invoke an external command when started; the
// vulnerability scan happens in process.
//
// It sets only the Path and Args in the returned structure.
//
// The returned Cmd's Args field is constructed from the command name (which is
// always unused, but present to model the exec.Command API), followed
// by the elements of arg, so arg should not include the command name itself.
//
// For example, Command("echo", "hello"). Args[0] is always name, not the
// possibly resolved Path.
//
// It is designed to be very easy to switch to running an external command
// instead.
func Command(ctx context.Context, arg ...string) *Cmd {
	return &Cmd{
		ctx:  ctx,
		args: arg,
	}
}

// Run starts govulncheck and waits for it to complete.
func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

// Start starts the specified command but does not wait for it to complete.
//
// After a successful call to Start the Wait method must be called in order to
// release associated system resources.
func (c *Cmd) Start() error {
	if c.done != nil {
		return errors.New("vuln: already started")
	}
	if c.Stdout == nil {
		c.Stdout = os.Stdout
	}
	c.done = make(chan struct{})
	go func() {
		defer func() {
			for _, cl := range c.closers {
				cl.Close()
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
	<-c.done
	return c.err
}

func (c *Cmd) scan() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	return doGovulncheck(c.ctx, c.Stdout, c.args)
}
