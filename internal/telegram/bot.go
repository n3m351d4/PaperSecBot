package telegram

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	openai "github.com/sashabaranov/go-openai"

	"papersecbot/internal/openaiutil"
)

const (
	startMessage   = "Привет! Используй /bug для начала работы."
	bugPrompt      = "Пришлите краткое описание — адреса, суть бага, запросы из Burp и прочую информацию."
	unknownCommand = "Неизвестная команда"
	startBugFirst  = "Сначала /bug."
	openaiTimeout  = "Время ожидания ответа от OpenAI истекло."
	markdownMode   = "Markdown"
)

// pendingChats tracks chats waiting for a bug description and is
// safe for concurrent access.
type pendingChats struct {
	mu    sync.Mutex
	chats map[int64]struct{}
}

// newPendingChats returns an initialized pendingChats value.
func newPendingChats() *pendingChats {
	return &pendingChats{chats: make(map[int64]struct{})}
}

// Add marks the specified chat as pending input.
func (p *pendingChats) Add(id int64) {
	p.mu.Lock()
	p.chats[id] = struct{}{}
	p.mu.Unlock()
}

// Remove deletes the chat from the pending list.
func (p *pendingChats) Remove(id int64) {
	p.mu.Lock()
	delete(p.chats, id)
	p.mu.Unlock()
}

// Has reports whether the chat is awaiting a description.
func (p *pendingChats) Has(id int64) bool {
	p.mu.Lock()
	_, ok := p.chats[id]
	p.mu.Unlock()
	return ok
}

// Cancel removes the chat from the pending list and returns true
// if it was present.
func (p *pendingChats) Cancel(id int64) bool {
	p.mu.Lock()
	_, ok := p.chats[id]
	if ok {
		delete(p.chats, id)
	}
	p.mu.Unlock()
	return ok
}

// Bot represents a Telegram bot with an optional OpenAI backend.
// TG is the Telegram API client, OA is the OpenAI client (may be nil),
// and Pending tracks chats currently describing a bug.
type Bot struct {
	TG      *tgbotapi.BotAPI
	OA      *openai.Client
	Pending *pendingChats
}

// New constructs a Bot instance from Telegram and OpenAI clients. The
// OpenAI client can be nil to disable description enrichment.
func New(tg *tgbotapi.BotAPI, oa *openai.Client) *Bot {
	return &Bot{TG: tg, OA: oa, Pending: newPendingChats()}
}

// HandleCmd processes bot commands such as /start, /bug and /cancel. Any
// unknown command results in a generic error message.
func (b *Bot) HandleCmd(m *tgbotapi.Message) {
	switch m.Command() {
	case "start":
		b.send(m.Chat.ID, startMessage)
	case "bug":
		if b.Pending.Has(m.Chat.ID) {
			b.send(m.Chat.ID, "Вы уже начали описание. Пришлите текст или /cancel.")
			return
		}
		b.Pending.Add(m.Chat.ID)
		b.send(m.Chat.ID, bugPrompt)
	case "cancel":
		if b.Pending.Cancel(m.Chat.ID) {
			b.send(m.Chat.ID, "Отменено. Используйте /bug, чтобы начать заново.")
		} else {
			b.send(m.Chat.ID, "Нет активного запроса.")
		}
	default:
		b.send(m.Chat.ID, unknownCommand)
	}
}

// HandleText expects a bug description from the user. The text is
// optionally enriched using OpenAI and the result is sent back as
// formatted Markdown. If the user did not start with /bug they are
// reminded to do so.
func (b *Bot) HandleText(m *tgbotapi.Message) {
	if !b.Pending.Has(m.Chat.ID) {
		b.send(m.Chat.ID, startBugFirst)
		return
	}
	desc := strings.TrimSpace(m.Text)
	b.Pending.Remove(m.Chat.ID)

	rep, err := openaiutil.ExtractFields(b.OA, desc)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "deadline") {
			b.send(m.Chat.ID, openaiTimeout)
		} else {
			b.send(m.Chat.ID, "OpenAI error: "+err.Error())
		}
		return
	}
	b.send(m.Chat.ID, openaiutil.BuildMarkdown(rep))
}

// send wraps sending a Markdown-formatted message to Telegram.
func (b *Bot) send(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = markdownMode
	if _, err := b.TG.Send(msg); err != nil {
		log.Printf("telegram send failed: %v", err)
		if _, err := b.TG.Send(msg); err != nil {
			log.Printf("telegram send retry failed: %v", err)
		}
	}
}
