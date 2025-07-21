package openaiutil

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"
)

var (
	codeBlockRE = regexp.MustCompile("(?s)```(?:json)?\\s*(.*?)```")
	urlRE       = regexp.MustCompile(`https?://[\w.-]+`)
)

const (
	defaultMaxTokens      = 10000
	defaultSeverity       = "High"
	defaultName           = "Безопасность"
	defaultCVSSScore      = "7.5"
	defaultCVSSVector     = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
	defaultScreenshotHint = "Подсказки для скриншотов"
	defaultRemediation    = "Рекомендации по исправлению"
	placeholder           = "—"
	systemPrompt          = "Ты Russian security-аналитик. Ответ JSON minified безбэктиков. Ключи: Severity, Name, CVSSScore, CVSSVector, Assets, ShortDesc, ScreenshotHints, Remediation. Severity на английском. ShortDesc — техническое описание на русском с PoC и влиянием. ScreenshotHints — русские подсказки какие скриншоты/артефакты/POC приложить. Remediation — детальные шаги с ссылками PortSwigger, Nessus и Acunetix (рус)."
)

// Report describes vulnerability report fields.
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

// reportAI mirrors Report but allows numeric CVSSScore from OpenAI
// for easier JSON parsing.
type reportAI struct {
	Severity        string      `json:"Severity"`
	Name            string      `json:"Name"`
	CVSSScore       json.Number `json:"CVSSScore"`
	CVSSVector      string      `json:"CVSSVector"`
	Assets          string      `json:"Assets"`
	ShortDesc       string      `json:"ShortDesc"`
	ScreenshotHints string      `json:"ScreenshotHints"`
	Remediation     string      `json:"Remediation"`
}

// ParseDomain extracts first domain from text or returns a placeholder.
func ParseDomain(text string) string {
	if m := urlRE.FindString(text); m != "" {
		if u, err := url.Parse(m); err == nil {
			return u.Host
		}
	}
	return placeholder
}

// BuildMarkdown returns a formatted message for Telegram.
func BuildMarkdown(r Report) string {
	val := func(s string) string {
		if s == "" {
			return placeholder
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

// callOpenAI sends the description to OpenAI and decodes the JSON response.
func callOpenAI(ctx context.Context, c *openai.Client, description string) (reportAI, error) {
	userPrompt := "Описание: " + description

	model := os.Getenv("OPENAI_MODEL")
	if model == "" {
		model = openai.GPT4o
	}

	maxTokens := defaultMaxTokens
	if v := os.Getenv("OPENAI_MAX_TOKENS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxTokens = n
		}
	}

	req := openai.ChatCompletionRequest{
		Model:       model,
		Messages:    []openai.ChatCompletionMessage{{Role: "system", Content: systemPrompt}, {Role: "user", Content: userPrompt}},
		Temperature: 0.2,
		MaxTokens:   maxTokens,
	}

	resp, err := c.CreateChatCompletion(ctx, req)
	if err != nil {
		return reportAI{}, fmt.Errorf("request failed: %w", err)
	}

	raw := strings.TrimSpace(resp.Choices[0].Message.Content)
	if m := codeBlockRE.FindStringSubmatch(raw); len(m) > 1 {
		raw = m[1]
	}

	var ai reportAI
	if err := json.Unmarshal([]byte(raw), &ai); err != nil {
		return reportAI{}, fmt.Errorf("invalid JSON: %w", err)
	}
	return ai, nil
}

// ExtractFields talks to OpenAI and fills a Report using the provided description.
// If client is nil no request is made and defaults are returned.
func ExtractFields(client *openai.Client, description string) (Report, error) {
	asset := ParseDomain(description)
	base := Report{
		Severity:        defaultSeverity,
		Name:            defaultName,
		CVSSScore:       defaultCVSSScore,
		CVSSVector:      defaultCVSSVector,
		Assets:          asset,
		ShortDesc:       description,
		ScreenshotHints: defaultScreenshotHint,
		Remediation:     defaultRemediation,
	}

	if client == nil {
		return base, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ai, err := callOpenAI(ctx, client, description)
	if err != nil {
		return base, fmt.Errorf("openai: %w", err)
	}
	if ai.Severity != "" {
		base.Severity = ai.Severity
	}
	if ai.Name != "" {
		base.Name = ai.Name
	}
	if s := ai.CVSSScore.String(); s != "" {
		base.CVSSScore = s
	}
	if ai.CVSSVector != "" {
		base.CVSSVector = ai.CVSSVector
	}
	if ai.Assets != "" {
		base.Assets = ai.Assets
	}
	if ai.ShortDesc != "" {
		base.ShortDesc = ai.ShortDesc
	}
	if ai.ScreenshotHints != "" {
		base.ScreenshotHints = ai.ScreenshotHints
	}
	if ai.Remediation != "" {
		base.Remediation = ai.Remediation
	}
	if base.Assets == "" {
		base.Assets = asset
	}
	return base, nil
}
