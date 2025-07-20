package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"

    tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
    openai "github.com/sashabaranov/go-openai"
)

var (
    codeBlockRE = regexp.MustCompile("(?s)```(?:json)?\\s*(.*?)```") // извлечение JSON
    urlRE       = regexp.MustCompile(`https?://[\w.-]+`)              // первый URL
)

type Bot struct {
    tg      *tgbotapi.BotAPI
    oa      *openai.Client
    pending map[int64]bool
    mu      sync.Mutex
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

    bot := &Bot{tg: tg, oa: oa, pending: make(map[int64]bool)}
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

    fields, err := b.extractFields(desc)
    if err != nil {
        b.send(m.Chat.ID, "OpenAI error: "+err.Error())
        return
    }
    b.send(m.Chat.ID, buildMarkdown(fields))
}

func (b *Bot) extractFields(description string) (map[string]string, error) {
    asset := parseDomain(description)
    base := map[string]string{
        "Severity":        "High",
        "Name":            "Безопасность",
        "CVSSScore":       "7.5",
        "CVSSVector":      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "Assets":          asset,
        "ShortDesc":       description,
        "ScreenshotHints": "Подсказки для скриншотов",
        "Remediation":     "Рекомендации по исправлению",
    }

    if b.oa == nil {
        return base, nil
    }

    ctx := context.Background()
    systemPrompt := "Ты Russian security-аналитик. Ответ JSON minified без бэктиков. Ключи: Severity, Name, CVSSScore, CVSSVector, Assets, ShortDesc, ScreenshotHints, Remediation. Severity на английском. ShortDesc — техническое описание на русском с PoC и влиянием. ScreenshotHints — русские подсказки какие скриншоты/артефакты/POC приложить. Remediation — детальные шаги с ссылками PortSwigger, Nessus и Acunetix (рус)."
    userPrompt := "Описание: " + description

    req := openai.ChatCompletionRequest{
        Model:       "gpt-4o",
        Messages:    []openai.ChatCompletionMessage{{Role: "system", Content: systemPrompt}, {Role: "user", Content: userPrompt}},
        Temperature: 0.2,
        MaxTokens:   10000,
    }

    resp, err := b.oa.CreateChatCompletion(ctx, req)
    if err != nil {
        return base, err
    }

    raw := strings.TrimSpace(resp.Choices[0].Message.Content)
    if m := codeBlockRE.FindStringSubmatch(raw); len(m) > 1 {
        raw = m[1]
    }

    var tmp map[string]interface{}
    if err := json.Unmarshal([]byte(raw), &tmp); err != nil {
        return base, err
    }

    for k, v := range tmp {
        base[k] = fmt.Sprint(v)
    }
    if base["Assets"] == "" {
        base["Assets"] = asset
    }
    return base, nil
}

func parseDomain(text string) string {
    if m := urlRE.FindString(text); m != "" {
        if u, err := url.Parse(m); err == nil {
            return u.Host
        }
    }
    return "—"
}

func buildMarkdown(d map[string]string) string {
    g := func(k string) string {
        if v, ok := d[k]; ok && v != "" {
            return v
        }
        return "—"
    }

    var sb strings.Builder
    cleanName := strings.TrimSpace(urlRE.ReplaceAllString(g("Name"), ""))

    sb.WriteString("**[" + g("Severity") + "] " + cleanName + "**\n")
    sb.WriteString("**CVSS:** " + g("CVSSScore") + " (" + g("CVSSVector") + ")\n")
    sb.WriteString("**Затронутые активы:** " + g("Assets") + "\n")
    sb.WriteString("**Краткое описание:** " + g("ShortDesc") + "\n\n")
    sb.WriteString("*" + g("ScreenshotHints") + "*\n\n")
    sb.WriteString("**Рекомендации:** " + g("Remediation") + "\n")

    return sb.String()
}

func (b *Bot) send(chatID int64, text string) {
    const limit = 4096
    for len(text) > 0 {
        chunk := text
        if len(chunk) > limit {
            chunk = chunk[:limit]
            if i := strings.LastIndex(chunk, "\n"); i > 0 {
                chunk = chunk[:i]
            }
        }

        msg := tgbotapi.NewMessage(chatID, chunk)
        msg.ParseMode = "Markdown"
        if _, err := b.tg.Send(msg); err != nil {
            log.Printf("send: %v", err)
            break
        }

        text = strings.TrimPrefix(text[len(chunk):], "\n")
    }
}
