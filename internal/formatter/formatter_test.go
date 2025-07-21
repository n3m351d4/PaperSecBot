package formatter_test

import (
	"strings"
	"testing"

	"papersecbot/internal/formatter"
	openaiutil "papersecbot/internal/openaiutil"
)

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
