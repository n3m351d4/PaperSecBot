package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	openai "github.com/sashabaranov/go-openai"
)

var (
	codeBlockRE = regexp.MustCompile("(?s)```(?:json)?\\s*(.*?)```") // извлечение JSON
	urlRE       = regexp.MustCompile(`https?://[\w.-]+`)             // первый URL
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

	startMessage   = "Привет! Используй /bug для начала работы."
	bugPrompt      = "Пришлите краткое описание — адреса, суть бага, запросы из Burp и прочую информацию."
	unknownCommand = "Неизвестная команда"
	startBugFirst  = "Сначала /bug."
	openaiTimeout  = "Время ожидания ответа от OpenAI истекло."
	markdownMode   = "Markdown"
	systemPrompt   = "Ты Russian security-аналитик. Ответ JSON minified без бэктиков. Ключи: Severity, Name, CVSSScore, CVSSVector, Assets, ShortDesc, ScreenshotHints, Remediation. Severity на английском. ShortDesc — техническое описание на русском с PoC и влиянием. ScreenshotHints — русские подсказки какие скриншоты/артефакты/POC приложить. Remediation — детальные шаги с ссылками PortSwigger, Nessus и Acunetix (рус)."
)

// Report описывает итоговую структуру отчёта
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

// pendingChats tracks chats waiting for a bug description.
type pendingChats struct {
	mu    sync.Mutex
	chats map[int64]struct{}
}

func newPendingChats() *pendingChats {
	return &pendingChats{chats: make(map[int64]struct{})}
}

func (p *pendingChats) Add(id int64) {
	p.mu.Lock()
	p.chats[id] = struct{}{}
	p.mu.Unlock()
}

func (p *pendingChats) Remove(id int64) {
	p.mu.Lock()
	delete(p.chats, id)
	p.mu.Unlock()
}

func (p *pendingChats) Has(id int64) bool {
	p.mu.Lock()
	_, ok := p.chats[id]
	p.mu.Unlock()
	return ok
}

// Cancel removes the chat from pending state and reports whether it was pending.
func (p *pendingChats) Cancel(id int64) bool {
	p.mu.Lock()
	_, ok := p.chats[id]
	if ok {
		delete(p.chats, id)
	}
	p.mu.Unlock()
	return ok
}

type Bot struct {
	tg      *tgbotapi.BotAPI
	oa      *openai.Client
	pending *pendingChats
}

func main() {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		log.Fatalln("TELEGRAM_BOT_TOKEN not set")
	}
	tg, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatalf("bot init: %v", err)
	}
	log.Printf("Authorized as %s", tg.Self.UserName)

	var oa *openai.Client
	if k := os.Getenv("OPENAI_API_KEY"); k != "" {
		oa = openai.NewClient(k)
	}

	bot := &Bot{tg: tg, oa: oa, pending: newPendingChats()}
	updates := tg.GetUpdatesChan(tgbotapi.UpdateConfig{Timeout: 60})
	for u := range updates {
		if u.Message == nil {
			continue
		}
		if u.Message.IsCommand() {
			bot.handleCmd(u.Message)
		} else {
			bot.handleText(u.Message)
		}
	}
}

func (b *Bot) handleCmd(m *tgbotapi.Message) {
	switch m.Command() {
	case "start":
		b.send(m.Chat.ID, startMessage)
	case "bug":
		if b.pending.Has(m.Chat.ID) {
			b.send(m.Chat.ID, "Вы уже начали описание. Пришлите текст или /cancel.")
			return
		}
		b.pending.Add(m.Chat.ID)
		b.send(m.Chat.ID, "Пришлите краткое описание — адреса, суть бага, запросы из Burp и прочую информацию.")
	case "cancel":
		if b.pending.Cancel(m.Chat.ID) {
			b.send(m.Chat.ID, "Отменено. Используйте /bug, чтобы начать заново.")
		} else {
			b.send(m.Chat.ID, "Нет активного запроса.")
		}
	default:
		b.send(m.Chat.ID, unknownCommand)
	}
}

func (b *Bot) handleText(m *tgbotapi.Message) {
	b.mu.Lock()
	waiting := b.pending[m.Chat.ID]
	b.mu.Unlock()
	if !waiting {
		b.send(m.Chat.ID, startBugFirst)

	if !b.pending.Has(m.Chat.ID) {
		b.send(m.Chat.ID, "Сначала /bug.")

		return
	}
	desc := strings.TrimSpace(m.Text)
	b.pending.Remove(m.Chat.ID)

	rep, err := b.extractFields(desc)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "deadline") {
			b.send(m.Chat.ID, openaiTimeout)
		} else {
			b.send(m.Chat.ID, "OpenAI error: "+err.Error())
		}
		return
	}
	b.send(m.Chat.ID, buildMarkdown(rep))
}

func (b *Bot) extractFields(description string) (Report, error) {
	asset := parseDomain(description)
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

	if b.oa == nil {
		return base, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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

	resp, err := b.oa.CreateChatCompletion(ctx, req)
	if err != nil {
		return base, err
	}

	raw := strings.TrimSpace(resp.Choices[0].Message.Content)
	if m := codeBlockRE.FindStringSubmatch(raw); len(m) > 1 {
		raw = m[1]
	}

	var ai reportAI
	if err := json.Unmarshal([]byte(raw), &ai); err != nil {
		return base, err
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

func parseDomain(text string) string {
	if m := urlRE.FindString(text); m != "" {
		if u, err := url.Parse(m); err == nil {
			return u.Host
		}
	}
	return placeholder
}

func buildMarkdown(r Report) string {
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

func (b *Bot) send(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = markdownMode
	_, _ = b.tg.Send(msg)
}
