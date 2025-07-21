package openaiutil

import (
	"strings"
	"testing"
)

func TestParseDomain(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"See https://example.com/path", "example.com"},
		{"Multiple https://foo.com and http://bar.com", "foo.com"},
		{"No url here", placeholder},
		{"ftp://ftp.example.com", placeholder},
		{"Text https://sub.domain.com/?q=1", "sub.domain.com"},
	}
	for i, tt := range tests {
		if got := ParseDomain(tt.in); got != tt.want {
			t.Errorf("%d: ParseDomain(%q)=%q want %q", i, tt.in, got, tt.want)
		}
	}
}

func TestBuildMarkdown(t *testing.T) {
	r := Report{
		Severity:        "High",
		Name:            "XSS at https://evil.com",
		CVSSScore:       "7.5",
		CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		Assets:          "test.com",
		ShortDesc:       "<script>",
		ScreenshotHints: "Look at console",
		Remediation:     "Escape < > &",
	}
	md := BuildMarkdown(r)
	if strings.Contains(md, "https://evil.com") {
		t.Errorf("url not stripped from name: %s", md)
	}
	if !strings.Contains(md, "[High] XSS at") {
		t.Errorf("severity/name missing: %s", md)
	}
}

func TestBuildMarkdownEmpty(t *testing.T) {
	r := Report{}
	md := BuildMarkdown(r)
	for _, field := range []string{"**[", "CVSS:", "Затронутые активы:", "Описание:", "*", "Рекомендации:"} {
		if !strings.Contains(md, field) {
			t.Errorf("missing field marker %s", field)
		}
	}
	if count := strings.Count(md, placeholder); count < 5 {
		t.Errorf("expected placeholder inserted, got %d", count)
	}
}
