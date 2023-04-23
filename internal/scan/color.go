// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package scan

import (
	"fmt"
	"strings"
	"text/template"
)

const (
	// These are all the constants for the terminal escape strings

	colorEscape = "\033["
	colorEnd    = "m"

	fgStart   = 30
	bgStart   = 40
	fgHiStart = 90
	bgHiStart = 100

	bright = "bright"

	colorReset     = colorEscape + "0" + colorEnd
	colorBold      = colorEscape + "1" + colorEnd
	colorFaint     = colorEscape + "2" + colorEnd
	colorUnderline = colorEscape + "4" + colorEnd
	colorBlink     = colorEscape + "5" + colorEnd
)

// these are the names for the terminal colors, in the same order as their numerical values
var colorNames = []string{
	"black",
	"red",
	"green",
	"yellow",
	"blue",
	"magenta",
	"cyan",
	"white",
}

// installColorFunctions is used to add the color functions to a template function map
func installColorFunctions(funcs template.FuncMap) {
	// fg returns a foreground color escape sequence.
	// If value is not nil, it will be wrapped in a color and reset pair, otherwise
	// only the color sequence will be returned.
	funcs["fg"] = func(name string) string { return color(name, fgStart, fgHiStart) }
	// bg returns a background color escape sequence.
	funcs["bg"] = func(name string) string { return color(name, bgStart, bgHiStart) }
	// reset returns a color reset escape sequence.
	funcs["reset"] = func() string { return colorReset }
	// reset returns a bold escape sequence.
	funcs["bold"] = func() string { return colorBold }
	// reset returns a faint color escape sequence.
	funcs["faint"] = func() string { return colorFaint }
	// reset returns an underline escape sequence.
	funcs["underline"] = func() string { return colorUnderline }
	// reset returns a text blink escape sequence.
	funcs["blink"] = func() string { return colorBlink }
}

// color builds a color escape sequence from a color name, color section offset and brightness.
func color(name string, baseOffset int, brightOffset int) string {
	offset := baseOffset
	if strings.HasPrefix(name, bright) {
		offset = brightOffset
		name = name[len(bright):]
	}
	for i, s := range colorNames {
		if s == name {
			return colorEscape + fmt.Sprint(offset+i) + colorEnd
		}
	}
	return "*invalid color*"
}
