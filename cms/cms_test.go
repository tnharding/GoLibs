package cms

import (
	"strings"
	"testing"
)

func TestUnmarshal(t *testing.T) {
	data := []byte("0\x05\f\x03a\xc9c")
	var result invalidUTF8Test
	_, err := Unmarshal(data, &result)

	const expectedSubstring = "UTF"
	if err == nil {
		t.Fatal("Successfully unmarshaled invalid UTF-8 data")
	} else if !strings.Contains(err.Error(), expectedSubstring) {
		t.Fatalf("Expected error to mention %q but error was %q", expectedSubstring, err.Error())
	}
}
