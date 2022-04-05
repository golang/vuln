package main

func linefrompc()
func pcfromline()

func main() {
	// Prevent GC of our test symbols
	linefrompc()
	pcfromline()
	inline1()
}

func inline1() {
	inline2()
}

func inline2() {
	println(1)
}
