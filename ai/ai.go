package ai

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"
	"papersecbot/report"
)

var codeBlockRE = regexp.MustCompile("(?s)```(?:json)?\\s*(.*?)```")

const defaultMaxTokens = 10000

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

// ExtractFields enriches a base report using OpenAI based on the description.
func ExtractFields(client *openai.Client, description string) (report.Report, error) {
	asset := report.ParseDomain(description)
	base := report.Report{
		Severity:        "High",
		Name:            "Безопасность",
		CVSSScore:       "7.5",
		CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		Assets:          asset,
		ShortDesc:       description,
		ScreenshotHints: "Подсказки для скриншотов",
		Remediation:     "Рекомендации по исправлению",
	}

	if client == nil {
		return base, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	systemPrompt := "Ты Russian security-аналитик. Ответ JSON minified без бектиков. Ключи: Severity, Name, CVSSScore, CVSSVector, Assets, ShortDesc, ScreenshotHints, Remediation. Severity на английском. ShortDesc — техническое описание на русском с PoC и влиянием. ScreenshotHints — русские подсказки какие скриншоты/артефакты/POC приложить. Remediation — детальные шаги с ссылками PortSwigger, Nessus и Acunetix (рус)."
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

	resp, err := client.CreateChatCompletion(ctx, req)
	if err != nil {
		return base, err
	}

	raw := strings.TrimSpace(resp.Choices[0].Message.Content)
	if m := codeBlockRE.FindStringSubmatch(raw); len(m) > 1 {
		raw = m[1]
	}

	var aiResp reportAI
	if err := json.Unmarshal([]byte(raw), &aiResp); err != nil {
		return base, err
	}
	if aiResp.Severity != "" {
		base.Severity = aiResp.Severity
	}
	if aiResp.Name != "" {
		base.Name = aiResp.Name
	}
	if s := aiResp.CVSSScore.String(); s != "" {
		base.CVSSScore = s
	}
	if aiResp.CVSSVector != "" {
		base.CVSSVector = aiResp.CVSSVector
	}
	if aiResp.Assets != "" {
		base.Assets = aiResp.Assets
	}
	if aiResp.ShortDesc != "" {
		base.ShortDesc = aiResp.ShortDesc
	}
	if aiResp.ScreenshotHints != "" {
		base.ScreenshotHints = aiResp.ScreenshotHints
	}
	if aiResp.Remediation != "" {
		base.Remediation = aiResp.Remediation
	}
	if base.Assets == "" {
		base.Assets = asset
	}
	return base, nil
}
