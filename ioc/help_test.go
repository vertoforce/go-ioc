package ioc

import (
	"fmt"
	"reflect"
	"testing"
)

func TestUniqueStringSlice(t *testing.T) {
	tests := []struct {
		input []string
		want  []string
	}{
		{
			[]string{"one", "one", "two", "two", "three", "three"},
			[]string{"one", "three", "two"},
		},
		{
			[]string{"one", "two", "three", "one", "two", "three", "three", "one", "one", "two", "two"},
			[]string{"one", "three", "two"},
		},
		{
			[]string{"three", "two", "one", "three", "three", "two", "two", "one"},
			[]string{"one", "three", "two"},
		},
	}

	for i, test := range tests {
		if got := uniqueStringSlice(test.input); !reflect.DeepEqual(got, test.want) {
			t.Errorf("Incorrect result for test: " + fmt.Sprint(i))
		}
	}
}
