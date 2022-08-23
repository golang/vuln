package main

import (
	"fmt"

	"github.com/tidwall/gjson"
	"golang.org/x/text/language"
)

func main() {
	fmt.Println("hello")
	language.Parse("")
	gjson.Valid("{hello: world}")
}
