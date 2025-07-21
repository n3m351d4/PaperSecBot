package formatter

import (
	"regexp"
	"strings"

	"papersecbot/internal/openaiutil"
)

// Placeholder represents missing value in formatted report.
const Placeholder = "—"

var urlRE = regexp.MustCompile(`https?://[\w.-]+`)

// escapeMarkdown escapes Markdown special characters.
func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"*", "\\*",
		"_", "\\_",
		"`", "\\`",
	)
	return replacer.Replace(s)
}

// BuildMarkdown formats the Report into a Markdown block for Telegram.
func BuildMarkdown(r openaiutil.Report) string {
	val := func(s string) string {
		if s == "" {
			return Placeholder
		}
		return escapeMarkdown(s)
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
