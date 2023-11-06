package main

func main() {
	f()
}

func f() {
	g()
	g()
}

func g() {
	println(1)
}
