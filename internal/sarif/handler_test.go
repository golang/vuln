// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sarif

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
)

func scanLevel(f *govulncheck.Finding) string {
	fr := f.Trace[0]
	if fr.Function != "" {
		return "symbol"
	}
	if fr.Package != "" {
		return "package"
	}
	return "module"
}

func TestHandlerSymbol(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson",
        "function": "Get",
        "receiver": "Result"
      },
      {
        "module": "golang.org/vuln",
        "package": "golang.org/vuln",
        "function": "main"
      }
    ]
  }
}`

	h := NewHandler(nil)
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "symbol",
		"GO-2021-0054": "package",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestHandlerPackage(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}`

	h := NewHandler(nil)
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "package",
		"GO-2021-0054": "package",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestHandlerModule(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}`

	h := NewHandler(nil)
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "module",
		"GO-2021-0054": "module",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestMoreSpecific(t *testing.T) {
	frame := func(m, p, f string) *govulncheck.Frame {
		return &govulncheck.Frame{
			Module:   m,
			Package:  p,
			Function: f,
		}
	}

	for _, tc := range []struct {
		name   string
		want   int
		trace1 []*govulncheck.Frame
		trace2 []*govulncheck.Frame
	}{
		{"sym-vs-sym", 0,
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m1", "p1", "f2")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v2"), frame("m1", "p1", "f1"), frame("m2", "p2", "f2")},
		},
		{"sym-vs-pkg", -1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m1", "p1", "f2")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
		},
		{"pkg-vs-sym", 1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m2", "p2", "v2")},
		},
		{"pkg-vs-mod", -1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
			[]*govulncheck.Frame{
				frame("m1", "", "")},
		},
		{"mod-vs-sym", 1,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v2"), frame("m1", "p1", "f1")},
		},
		{"mod-vs-mod", 0,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m2", "", "")},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f1 := &govulncheck.Finding{Trace: tc.trace1}
			f2 := &govulncheck.Finding{Trace: tc.trace2}
			if got := moreSpecific(f1, f2); got != tc.want {
				t.Errorf("want %d; got %d", tc.want, got)
			}
		})
	}
}
