package main

import (
	"archive/zip"
	"fmt"
)

func main() {
	_, err := zip.OpenReader("file.zip")
	fmt.Println(err)
}
