package openaiutil_test

import (
	"testing"

	"papersecbot/internal/formatter"
	openaiutil "papersecbot/internal/openaiutil"
)

func TestParseDomain(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"See https://example.com/path", "example.com"},
		{"Multiple https://foo.com and http://bar.com", "foo.com"},
		{"No url here", formatter.Placeholder},
		{"ftp://ftp.example.com", formatter.Placeholder},
		{"Text https://sub.domain.com/?q=1", "sub.domain.com"},
	}
	for i, tt := range tests {
		if got := openaiutil.ParseDomain(tt.in); got != tt.want {
			t.Errorf("%d: ParseDomain(%q)=%q want %q", i, tt.in, got, tt.want)
		}
	}
}
