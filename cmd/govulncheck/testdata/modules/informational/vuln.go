package main

import (
	"fmt"

	"github.com/tidwall/gjson"
)

func main() {
	fmt.Println("hello")
	gjson.Valid("{hello: world}")
}
