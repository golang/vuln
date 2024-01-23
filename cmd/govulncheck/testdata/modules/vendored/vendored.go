package main

import (
	"encoding/pem"

	"private.com/privateuser/fakemod"

	"golang.org/x/text/language"
)

func main() {
	fakemod.Leave()
	language.Parse("")
	_, _ = pem.Decode([]byte("test"))
}
