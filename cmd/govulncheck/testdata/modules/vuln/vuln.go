package main

import (
	"encoding/pem"
	"fmt"

	"github.com/tidwall/gjson"
	"golang.org/x/text/language"
)

func main() {
	fmt.Println("hello")
	language.Parse("")
	gjson.Valid("{hello: world}")
	_, _ = pem.Decode([]byte("test"))
}
