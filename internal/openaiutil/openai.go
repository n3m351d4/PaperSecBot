package openaiutil

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"
)

// AIClient is the interface implemented by types that can perform a
// chat completion request. It is satisfied by *openai.Client and can be
// mocked in tests.
type AIClient interface {
	CreateChatCompletion(ctx context.Context, req openai.ChatCompletionRequest) (openai.ChatCompletionResponse, error)
}

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

// Report contains all fields needed for a vulnerability description
// that will be sent back to the user. Each field corresponds to a
// part of the Markdown template built in BuildMarkdown.
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

// ParseDomain extracts the first URL domain found in the provided text.
// If no domain is present, a placeholder value is returned.
func ParseDomain(text string) string {
	if m := urlRE.FindString(text); m != "" {
		if u, err := url.Parse(m); err == nil {
			return u.Host
		}
	}
	return placeholder
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"*", "\\*",
		"_", "\\_",
		"`", "\\`",
	)
	return replacer.Replace(s)
}

// BuildMarkdown formats the Report into a human readable Markdown block that
// can be sent back to the user via Telegram.
func BuildMarkdown(r Report) string {
	val := func(s string) string {
		if s == "" {
			return placeholder
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

// callOpenAI sends the description to OpenAI and decodes the JSON response.
// It is used internally by ExtractFields.
func callOpenAI(ctx context.Context, c AIClient, description string) (reportAI, error) {
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

	log.Printf("OpenAI request model=%s", model)
	resp, err := c.CreateChatCompletion(ctx, req)
	if err != nil {
		log.Printf("OpenAI request failed: %v", err)
		return reportAI{}, fmt.Errorf("request failed: %w", err)
	}
	log.Printf("OpenAI response received")

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

// ExtractFields sends the bug description to OpenAI and fills a Report
// with the parsed response. If the OpenAI client is nil, only default
// values and the detected domain are returned.
func ExtractFields(client AIClient, description string) (Report, error) {
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

	log.Printf("sending description to OpenAI")
	ai, err := callOpenAI(ctx, client, description)
	if err == nil {
		log.Printf("received OpenAI result")
	}
	if err != nil {
		log.Printf("OpenAI processing error: %v", err)
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
