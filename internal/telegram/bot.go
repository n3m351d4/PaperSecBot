package telegram

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"papersecbot/internal/formatter"
	"papersecbot/internal/openaiutil"
)

const (
	startMessage       = "Привет! Используй /bug для начала работы."
	bugPrompt          = "Пришлите краткое описание — адреса, суть бага, запросы из Burp и прочую информацию."
	unknownCommand     = "Неизвестная команда"
	startBugFirst      = "Сначала /bug."
	openaiTimeout      = "Время ожидания ответа от OpenAI истекло."
	markdownMode       = "Markdown"
	alreadyStartedMsg  = "Вы уже начали описание. Пришлите текст или /cancel."
	canceledMsg        = "Отменено. Используйте /bug, чтобы начать заново."
	noActiveRequestMsg = "Нет активного запроса."
	openaiErrorPrefix  = "OpenAI error: "
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

// Bot wraps a Telegram client and optionally an OpenAI client.
// TelegramBot is the Telegram API client, OpenAIClient may be nil when
// OpenAI integration is disabled, and Pending tracks chats that are in the
// middle of describing a bug.
type Bot struct {
	TelegramBot  *tgbotapi.BotAPI
	OpenAIClient openaiutil.AIClient
	Pending      *pendingChats
}

// New creates a Bot from Telegram and OpenAI clients. Passing a nil OpenAI
// client disables description enrichment.
func New(telegramBot *tgbotapi.BotAPI, openAIClient openaiutil.AIClient) *Bot {
	return &Bot{TelegramBot: telegramBot, OpenAIClient: openAIClient, Pending: newPendingChats()}
}

// HandleCmd processes bot commands such as /start, /bug and /cancel. Any
// unknown command results in a generic error message.
func (b *Bot) HandleCmd(m *tgbotapi.Message) {
	log.Printf("handle command %s from %d", m.Command(), m.Chat.ID)
	switch m.Command() {
	case "start":
		b.send(m.Chat.ID, startMessage)
	case "bug":
		if b.Pending.Has(m.Chat.ID) {
			b.send(m.Chat.ID, alreadyStartedMsg)
			return
		}
		b.Pending.Add(m.Chat.ID)
		b.send(m.Chat.ID, bugPrompt)
	case "cancel":
		if b.Pending.Cancel(m.Chat.ID) {
			b.send(m.Chat.ID, canceledMsg)
		} else {
			b.send(m.Chat.ID, noActiveRequestMsg)
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
	log.Printf("handle text from %d", m.Chat.ID)
	if !b.Pending.Has(m.Chat.ID) {
		b.send(m.Chat.ID, startBugFirst)
		return
	}
	desc := strings.TrimSpace(m.Text)
	b.Pending.Remove(m.Chat.ID)
	log.Printf("calling OpenAI for chat %d", m.Chat.ID)
	rep, err := openaiutil.ExtractFields(b.OpenAIClient, desc)
	if err == nil {
		log.Printf("OpenAI success for chat %d", m.Chat.ID)
	}
	if err != nil {
		log.Printf("OpenAI error for chat %d: %v", m.Chat.ID, err)
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "deadline") {
			b.send(m.Chat.ID, openaiTimeout)
		} else {
			b.send(m.Chat.ID, openaiErrorPrefix+err.Error())
		}
		return
	}
	b.send(m.Chat.ID, formatter.BuildMarkdown(rep))
}

// send wraps sending a Markdown-formatted message to Telegram.
func (b *Bot) send(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = markdownMode
	if _, err := b.TelegramBot.Send(msg); err != nil {
		log.Printf("telegram send failed: %v", err)
		if _, err := b.TelegramBot.Send(msg); err != nil {
			log.Printf("telegram send retry failed: %v", err)
		}
	}
}
