// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosym

import (
	"debug/elf"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestInlineTree(t *testing.T) {
	pclinetestBinary, cleanup := dotest(t)
	defer cleanup()

	f, err := elf.Open(pclinetestBinary)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pclndat, err := f.Section(".gopclntab").Data()
	if err != nil {
		t.Fatalf("reading %s gopclntab: %v", pclinetestBinary, err)
	}

	// The test binaries will be compiled with the same Go version
	// used to run the tests.
	goFunc := lookupSymbol(f, FuncSymName(runtime.Version()))
	if goFunc == nil {
		t.Fatal("couldn't find go.func.*")
	}
	prog := progContaining(f, goFunc.Value)
	if prog == nil {
		t.Fatal("couldn't find go.func.* Prog")
	}
	pcln := NewLineTable(pclndat, f.Section(".text").Addr)
	s := f.Section(".gosymtab")
	if s == nil {
		t.Fatal("no .gosymtab section")
	}
	d, err := s.Data()
	if err != nil {
		t.Fatal(err)
	}
	tab, err := NewTable(d, pcln)
	if err != nil {
		t.Fatal(err)
	}

	fun := tab.LookupFunc("main.main")
	got, err := pcln.InlineTree(fun, goFunc.Value, prog.Vaddr, prog.ReaderAt)
	if err != nil {
		t.Fatal(err)
	}
	want := []InlinedCall{
		{FuncID: 0, Name: "main.inline1"},
		{FuncID: 0, Name: "main.inline2"},
	}
	if !cmp.Equal(got, want, cmpopts.IgnoreFields(InlinedCall{}, "ParentPC")) {
		t.Errorf("got\n%+v\nwant\n%+v", got, want)
	}
}

func progContaining(f *elf.File, addr uint64) *elf.Prog {
	for _, p := range f.Progs {
		if addr >= p.Vaddr && addr < p.Vaddr+p.Filesz {
			return p
		}
	}
	return nil
}

func lookupSymbol(f *elf.File, name string) *elf.Symbol {
	syms, err := f.Symbols()
	if err != nil {
		return nil
	}
	for _, s := range syms {
		if s.Name == name {
			return &s
		}
	}
	return nil
}
