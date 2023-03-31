// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"testing"
)

func TestTmplResultFuncs(t *testing.T) {
	for _, test := range []struct {
		name            string
		input           []tmplVulnInfo
		affectedCount   int
		unaffectedCount int
		affectedModules int
		stdlibAffected  bool
	}{
		{
			"stdlib affected",
			[]tmplVulnInfo{
				{
					Affected: true,
					Modules:  []tmplModVulnInfo{{IsStd: true}},
				},
			},
			1,
			0,
			0,
			true,
		},
		{
			"stdlib unaffected",
			[]tmplVulnInfo{
				{
					Affected: false,
					Modules:  []tmplModVulnInfo{{IsStd: true}},
				},
			},
			0,
			1,
			0,
			false,
		},
		{
			"module and stdlib affected",
			[]tmplVulnInfo{
				{
					Affected: true,
					Modules:  []tmplModVulnInfo{{IsStd: true}},
				},
				{
					Affected: true,
					Modules:  []tmplModVulnInfo{{IsStd: false}},
				},
			},
			2,
			0,
			1,
			true,
		},
		{
			"module unaffected and stdlib affected",
			[]tmplVulnInfo{
				{
					Affected: true,
					Modules:  []tmplModVulnInfo{{IsStd: true}},
				},
				{
					Affected: false,
					Modules:  []tmplModVulnInfo{{IsStd: false}},
				},
			},
			1,
			1,
			0,
			true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := affectedCount(test.input); got != test.affectedCount {
				t.Errorf("affectedCount = %d; want = %d", got, test.affectedCount)
			}
			if got := unaffectedCount(test.input); got != test.unaffectedCount {
				t.Errorf("unaffectedCount = %d; want = %d", got, test.unaffectedCount)
			}
			if got := affectedModules(test.input); got != test.affectedModules {
				t.Errorf("affectedModules = %d; want = %d", got, test.affectedModules)
			}
			if got := stdlibAffected(test.input); got != test.stdlibAffected {
				t.Errorf("stdlibAffected = %t; want = %t", got, test.stdlibAffected)
			}
		})
	}
}
