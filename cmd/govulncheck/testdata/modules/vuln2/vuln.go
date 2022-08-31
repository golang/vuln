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
	_ = gjson.Get("json", "path")
	_ = gjson.GetBytes([]byte("json"), "path")
}
