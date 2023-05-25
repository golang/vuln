package gjson

var prevent_optimization int

type Result struct{}

func (Result) Get(string) {
	Get("", "")
}

func Get(json, path string) Result {
	prevent_optimization++
	return Result{}
}
