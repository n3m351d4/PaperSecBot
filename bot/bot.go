package bot

import (
	"context"
	"errors"
	"strings"
	"sync"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	openai "github.com/sashabaranov/go-openai"

	"papersecbot/ai"
	"papersecbot/report"
)

// Bot wraps Telegram and OpenAI clients.
type Bot struct {
	tg      *tgbotapi.BotAPI
	oa      *openai.Client
	pending map[int64]bool
	mu      sync.Mutex
}

// New creates a Bot instance.
func New(tg *tgbotapi.BotAPI, oa *openai.Client) *Bot {
	return &Bot{tg: tg, oa: oa, pending: make(map[int64]bool)}
}

// HandleUpdate processes a single Telegram update.
func (b *Bot) HandleUpdate(u tgbotapi.Update) {
	if u.Message == nil {
		return
	}
	if u.Message.IsCommand() {
		b.handleCmd(u.Message)
	} else {
		b.handleText(u.Message)
	}
}

func (b *Bot) handleCmd(m *tgbotapi.Message) {
	switch m.Command() {
	case "start":
		b.send(m.Chat.ID, "Привет! Используй /bug для начала работы.")
	case "bug":
		b.mu.Lock()
		b.pending[m.Chat.ID] = true
		b.mu.Unlock()
		b.send(m.Chat.ID, "Пришлите краткое описание — адреса, суть бага, запросы из Burp и прочую информацию.")
	default:
		b.send(m.Chat.ID, "Неизвестная команда")
	}
}

func (b *Bot) handleText(m *tgbotapi.Message) {
	b.mu.Lock()
	waiting := b.pending[m.Chat.ID]
	b.mu.Unlock()
	if !waiting {
		b.send(m.Chat.ID, "Сначала /bug.")
		return
	}
	desc := strings.TrimSpace(m.Text)
	b.mu.Lock()
	delete(b.pending, m.Chat.ID)
	b.mu.Unlock()

	rep, err := ai.ExtractFields(b.oa, desc)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "deadline") {
			b.send(m.Chat.ID, "Время ожидания ответа от OpenAI истекло.")
		} else {
			b.send(m.Chat.ID, "OpenAI error: "+err.Error())
		}
		return
	}
	b.send(m.Chat.ID, report.BuildMarkdown(rep))
}

func (b *Bot) send(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	_, _ = b.tg.Send(msg)
}
