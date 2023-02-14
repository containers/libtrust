package libtrust

import (
	"testing"
)

func TestBase64URL(t *testing.T) {
	clean := "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSnVKcmlwUTF3IiwicDJjIjo0MDk2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiandrK2pzb24ifQ"

	tests := []string{
		clean, // clean roundtrip
		"eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2\nZF9DSnVKcmlwUTF3IiwicDJjIjo0MDk2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2\nIiwiY3R5IjoiandrK2pzb24ifQ",     // with newlines
		"eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2 \n ZF9DSnVKcmlwUTF3IiwicDJjIjo0MDk2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2 \n IiwiY3R5IjoiandrK2pzb24ifQ", // with newlines and spaces
	}

	for i, test := range tests {
		b, err := joseBase64UrlDecode(test)
		if err != nil {
			t.Fatalf("on test %d: %s", i, err)
		}
		got := joseBase64UrlEncode(b)

		if got != clean {
			t.Errorf("expected %q, got %q", clean, got)
		}
	}
}
