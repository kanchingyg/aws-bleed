package awslive

import (
	"errors"
	"testing"
)

func TestPaginateWithToken(t *testing.T) {
	pages := [][]int{
		{1, 2},
		{3},
		{4, 5},
	}
	tokens := []string{"page2", "page3", ""}
	calls := 0
	all, err := PaginateWithToken(func(token *string) ([]int, *string, error) {
		if calls >= len(pages) {
			return nil, nil, errors.New("unexpected page")
		}
		page := pages[calls]
		var next *string
		if tokens[calls] != "" {
			n := tokens[calls]
			next = &n
		}
		calls++
		return page, next, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 2, 3, 4, 5}
	if len(all) != len(want) {
		t.Fatalf("got %v want %v", all, want)
	}
	for i := range want {
		if all[i] != want[i] {
			t.Fatalf("got %v want %v", all, want)
		}
	}
	if calls != 3 {
		t.Fatalf("calls %d", calls)
	}
}
