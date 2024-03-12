package main

import (
	"io"
	"log"
	"net/http"
)

func main() {
	// Hello world, the web server

	helloHandler := func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	}

	http.HandleFunc("/hello", helloHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))

	// Test issue #66139
	log.Fatal(work[string]("golang"))
}

func work[T any](t T) error {
	log.Printf("%v\n", t)
	return http.Serve(nil, nil)
}
