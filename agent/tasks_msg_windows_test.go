package agent

import "testing"

func TestSanitizeShutdownMsg(t *testing.T) {
	cases := map[string]string{
		"":               "",
		`save "now"`:     "save 'now'",
		"line1\r\nline2": "line1  line2",
		`C:\path\`:       `C:\path`,
		"  padded  ":     "padded",
	}
	for in, want := range cases {
		if got := sanitizeShutdownMsg(in); got != want {
			t.Errorf("sanitizeShutdownMsg(%q) = %q, want %q", in, got, want)
		}
	}
	long := make([]rune, 600)
	for i := range long {
		long[i] = 'é'
	}
	if got := []rune(sanitizeShutdownMsg(string(long))); len(got) != 512 {
		t.Errorf("expected 512 runes, got %d", len(got))
	}
}
