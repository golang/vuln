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

type Cmd struct {
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Stdin  io.Reader
	Stdout io.WriteCloser
	Stderr io.WriteCloser

	ctx  context.Context
	done chan struct{}
	err  error
}

// Command is the equivalent of exec.Command
// It produces a struct with much of equivalent behaviors, except that instead
// of invoking an external command when started it will instead do the
// vulnerability scan in process.
// It is designed to be very easy to switch to running an external command
// instead.
func Command(ctx context.Context, name string, arg ...string) *Cmd {
	if ctx == nil {
		panic("nil Context")
	}
	return &Cmd{
		Path: name,
		Args: append([]string{name}, arg...),

		ctx: ctx,
	}
}

func (c *Cmd) String() string {
	b := new(strings.Builder)
	b.WriteString(c.Path)
	for _, a := range c.Args[1:] {
		b.WriteByte(' ')
		b.WriteString(a)
	}
	return b.String()
}

func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

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
	return doGovulncheck(cfg, c.Stdout)
}
