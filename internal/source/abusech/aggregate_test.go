package abusech

import (
	"reflect"
	"testing"
)

func TestIsSHA256(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "valid lowercase", in: "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48", want: true},
		{name: "valid uppercase", in: "1E934F76B891D4BE57A5EF60FDF52235D10CCADA12B061645238CF4F68B02B48", want: true},
		{name: "too short", in: "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b", want: false},
		{name: "too long", in: "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48aa", want: false},
		{name: "non-hex chars", in: "zz934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48", want: false},
		{name: "empty", in: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSHA256(tc.in); got != tc.want {
				t.Fatalf("isSHA256(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseHashList(t *testing.T) {
	valid1 := "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"
	valid2 := "3f191c8e0d0f8e5a2d5c515c7868aea3b2e3529222e90a82cc90ed1ba6bcfdb0"

	body := "# abuse.ch MalwareBazaar sha256 hash list\r\n" +
		"# Last updated: 2026-09-18\r\n" +
		"\r\n" +
		valid1 + "\r\n" +
		"\"" + valid2 + "\"\r\n" +
		"not-a-valid-hash\r\n" +
		"\r\n"

	got := parseHashList([]byte(body))
	want := []string{valid1, valid2}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseHashList() = %v, want %v", got, want)
	}
}
