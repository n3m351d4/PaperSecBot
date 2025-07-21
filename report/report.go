package report

import (
	"net/url"
	"regexp"
	"strings"
)

var urlRE = regexp.MustCompile(`https?://[\w.-]+`)

// Report describes vulnerability details returned to the user.
type Report struct {
	Severity        string
	Name            string
	CVSSScore       string
	CVSSVector      string
	Assets          string
	ShortDesc       string
	ScreenshotHints string
	Remediation     string
}

// ParseDomain returns the host part of the first URL in the text.
func ParseDomain(text string) string {
	if m := urlRE.FindString(text); m != "" {
		if u, err := url.Parse(m); err == nil {
			return u.Host
		}
	}
	return "—"
}

// BuildMarkdown renders the report as a Markdown snippet.
func BuildMarkdown(r Report) string {
	val := func(s string) string {
		if s == "" {
			return "—"
		}
		return s
	}

	var sb strings.Builder
	cleanName := strings.TrimSpace(urlRE.ReplaceAllString(val(r.Name), ""))

	sb.WriteString("**[" + val(r.Severity) + "] " + cleanName + "**\n")
	sb.WriteString("**CVSS:** " + val(r.CVSSScore) + " (" + val(r.CVSSVector) + ")\n")
	sb.WriteString("**Затронутые активы:** " + val(r.Assets) + "\n\n")
	sb.WriteString("**Описание:**\n" + val(r.ShortDesc) + "\n\n")
	sb.WriteString("*" + val(r.ScreenshotHints) + "*\n\n")
	sb.WriteString("**Рекомендации:**\n" + val(r.Remediation) + "\n")

	return sb.String()
}
