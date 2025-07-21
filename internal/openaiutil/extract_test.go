package openaiutil

import (
	"context"
	"testing"

	openai "github.com/sashabaranov/go-openai"
)

type mockAI struct {
	resp openai.ChatCompletionResponse
	err  error
}

func (m *mockAI) CreateChatCompletion(ctx context.Context, req openai.ChatCompletionRequest) (openai.ChatCompletionResponse, error) {
	return m.resp, m.err
}

func TestExtractFieldsDefaults(t *testing.T) {
	desc := "See https://example.com/path"
	got, err := ExtractFields(nil, desc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Assets != "example.com" {
		t.Errorf("assets=%s want example.com", got.Assets)
	}
	if got.ShortDesc != desc {
		t.Errorf("short desc=%s want %s", got.ShortDesc, desc)
	}
	if got.Severity != defaultSeverity {
		t.Errorf("severity=%s want %s", got.Severity, defaultSeverity)
	}
}

func TestExtractFieldsAI(t *testing.T) {
	m := &mockAI{resp: openai.ChatCompletionResponse{
		Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: `{"Severity":"Medium","Name":"SQL","CVSSScore":6.1,"CVSSVector":"AV:N","Assets":"test.com","ShortDesc":"desc","ScreenshotHints":"hint","Remediation":"fix"}`}}},
	}}
	got, err := ExtractFields(m, "text")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "Medium" || got.Name != "SQL" || got.CVSSScore != "6.1" || got.CVSSVector != "AV:N" || got.Assets != "test.com" || got.ShortDesc != "desc" || got.ScreenshotHints != "hint" || got.Remediation != "fix" {
		t.Errorf("unexpected result: %+v", got)
	}
}
