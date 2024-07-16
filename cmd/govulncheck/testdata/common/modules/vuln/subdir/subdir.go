package subdir

import (
	"github.com/tidwall/gjson"
)

func Foo() {
	gjson.Result{}.Get("")
}
