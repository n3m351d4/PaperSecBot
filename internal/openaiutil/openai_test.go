package openaiutil_test

import (
	"strings"
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

func TestBuildMarkdown(t *testing.T) {
	r := openaiutil.Report{
		Severity:        "High",
		Name:            "XSS at https://evil.com",
		CVSSScore:       "7.5",
		CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		Assets:          "test.com",
		ShortDesc:       "<script>",
		ScreenshotHints: "Look at console",
		Remediation:     "Escape < > &",
	}
	md := formatter.BuildMarkdown(r)
	if strings.Contains(md, "https://evil.com") {
		t.Errorf("url not stripped from name: %s", md)
	}
	if !strings.Contains(md, "[High] XSS at") {
		t.Errorf("severity/name missing: %s", md)
	}
}

func TestBuildMarkdownEmpty(t *testing.T) {
	r := openaiutil.Report{}
	md := formatter.BuildMarkdown(r)
	for _, field := range []string{"**[", "CVSS:", "Затронутые активы:", "Описание:", "*", "Рекомендации:"} {
		if !strings.Contains(md, field) {
			t.Errorf("missing field marker %s", field)
		}
	}
	if count := strings.Count(md, formatter.Placeholder); count < 5 {
		t.Errorf("expected placeholder inserted, got %d", count)
	}
}
