// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"testing"
)

func TestWrap(t *testing.T) {
	const width = 10
	for _, test := range []struct {
		in, want string
	}{
		{"", ""},
		{"foo", "foo"},
		{"omnivorous", "omnivorous"},   // equals width
		{"carnivorous", "carnivorous"}, // exceeds width
		{
			"A carnivorous beast.",
			"A\ncarnivorous\nbeast.",
		},
		{
			"An omnivorous beast.",
			"An\nomnivorous\nbeast.",
		},
		{
			"A nivorous beast.",
			"A nivorous\nbeast.",
		},
		{
			"Carnivorous beasts of the forest primeval.",
			"Carnivorous\nbeasts of\nthe forest\nprimeval.",
		},
		{
			"Able was I ere I saw Elba.",
			"Able was I\nere I saw\nElba.",
		},
	} {
		got := wrap(test.in, width)
		if got != test.want {
			t.Errorf("\ngot:\n%s\n\nwant:\n%s", got, test.want)
		}
	}
}
