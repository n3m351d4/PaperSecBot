package telegram

import (
	"context"
	"errors"
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

// pendingChats tracks chats waiting for a bug description.
type pendingChats struct {
	mu    sync.Mutex
	chats map[int64]struct{}
}

func newPendingChats() *pendingChats { return &pendingChats{chats: make(map[int64]struct{})} }

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

func (p *pendingChats) Cancel(id int64) bool {
	p.mu.Lock()
	_, ok := p.chats[id]
	if ok {
		delete(p.chats, id)
	}
	p.mu.Unlock()
	return ok
}

// Bot represents Telegram bot with OpenAI backend.
type Bot struct {
	TG      *tgbotapi.BotAPI
	OA      *openai.Client
	Pending *pendingChats
}

func New(tg *tgbotapi.BotAPI, oa *openai.Client) *Bot {
	return &Bot{TG: tg, OA: oa, Pending: newPendingChats()}
}

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

func (b *Bot) send(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = markdownMode
	_, _ = b.TG.Send(msg)
}
