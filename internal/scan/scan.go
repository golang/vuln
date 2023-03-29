// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
)

// Cmd represents an external govulncheck command being prepared or run,
// similar to exec.Cmd.
type Cmd struct {
	// Path is not used and exists only to model Cmd after exec.Cmd.
	Path string

	// Args holds command line arguments, including the command as Args[0].
	// If the Args field is empty or nil, Run uses {Path}.
	//
	// In typical use, both Path and Args are set by calling Command.
	Args []string

	// Env is not used and exists only to model Cmd after exec.Cmd.
	Env []string

	// Dir specifies the working directory of the command.
	//
	// If Dir is the empty string, Run runs the command in the
	// current directory.
	Dir string

	// Stdin specifies the standard input.
	//
	// If Stdin is nil, Stdin is set to os.Stdin.
	Stdin io.Reader

	// Stdout and Stderr specify the standard output and error.
	//
	// If either is nil, Run connects os.Stdout and os.Stderr respectively.
	Stdout io.WriteCloser
	Stderr io.WriteCloser

	ctx  context.Context
	done chan struct{}
	err  error
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
func Command(ctx context.Context, name string, arg ...string) *Cmd {
	return &Cmd{
		Path: name,
		Args: append([]string{name}, arg...),
		ctx:  ctx,
	}
}

// String returns a human-readable description of c. It is intended only for
// debugging. In particular, it is not suitable for use as input to a shell. The
// output of String may vary across releases.
func (c *Cmd) String() string {
	b := new(strings.Builder)
	b.WriteString(c.Path)
	for _, a := range c.Args[1:] {
		b.WriteByte(' ')
		b.WriteString(a)
	}
	return b.String()
}

// Run starts govulncheck and waits for it to complete.
//
// The returned error is nil if the command runs, has no problems copying
// stdin, stdout, and stderr, and without an error.
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
		defer close(c.done)
		defer func() {
			if c.Stdout != os.Stdout {
				c.Stdout.Close()
			}
			if c.Stderr != os.Stderr {
				c.Stderr.Close()
			}
		}()
		c.err = c.scan()
	}()
	return nil
}

// Wait waits for the command to exit and waits for any copying to stdin or
// copying from stdout or stderr to complete.
//
// The command must have been started by Start.
//
// The returned error is nil if the command runs, has no problems copying
// stdin, stdout, and stderr, and without an error.
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
	cfg, err := c.parseFlags()
	if err != nil {
		return err
	}
	return doGovulncheck(c.ctx, cfg, c.Stdout)
}
