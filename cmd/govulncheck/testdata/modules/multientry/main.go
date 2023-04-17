package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	args := os.Args[1:]

	// Calls foo which directly calls language.Parse.
	A()

	// Also calls foo which directly calls language.Parse.
	B()

	// Calls language.Parse directly.
	//
	// This will be displayed by govulncheck, since it is the shortest path.
	C()

	// Calls foobar which eventually calls language.MustParse (different
	// symbol, same report)
	D()

	// Calls moreFoo which directly calls language.Parse.
	E(args)

	// Calls stillMoreFoo which directly calls language.Parse.
	F(args)
}

func A() {
	foo(os.Args[1:])
}

func B() {
	foo(os.Args[1:])
}

func C() {
	_, _ = language.Parse("")
}

func D() {
	foobar()
}

func E(args []string) {
	moreFoo(args)
}

func F(args []string) {
	stillMoreFoo(args)
}

func foo(args []string) {
	for _, arg := range args {
		tag, err := language.Parse(arg)
		if err != nil {
			fmt.Printf("%s: error: %v\n", arg, err)
		} else if tag == language.Und {
			fmt.Printf("%s: undefined\n", arg)
		} else {
			fmt.Printf("%s: tag %s\n", arg, tag)
		}
	}
}

func moreFoo(args []string) {
	for _, arg := range args {
		tag, err := language.Parse(arg)
		if err != nil {
			fmt.Printf("%s: error: %v\n", arg, err)
		} else if tag == language.Und {
			fmt.Printf("%s: undefined\n", arg)
		} else {
			fmt.Printf("%s: tag %s\n", arg, tag)
		}
	}
}

func stillMoreFoo(args []string) {
	for _, arg := range args {
		tag, err := language.Parse(arg)
		if err != nil {
			fmt.Printf("%s: error: %v\n", arg, err)
		} else if tag == language.Und {
			fmt.Printf("%s: undefined\n", arg)
		} else {
			fmt.Printf("%s: tag %s\n", arg, tag)
		}
	}
}

func foobar() {
	language.MustParse("")
}
