//go:build twocallstacks

package main

import "golang.org/x/text/language"

func init() {
	language.ParseAcceptLanguage("")
}
