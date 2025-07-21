package main

import (
	"log"
	"os"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	openai "github.com/sashabaranov/go-openai"

	"papersecbot/internal/openaiutil"
	"papersecbot/internal/telegram"
)

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

	var oa openaiutil.AIClient
	if k := os.Getenv("OPENAI_API_KEY"); k != "" {
		oa = openai.NewClient(k)
	}

	bot := telegram.New(tg, oa)
	updates := tg.GetUpdatesChan(tgbotapi.UpdateConfig{Timeout: 60})
	for u := range updates {
		if u.Message == nil {
			continue
		}
		upd := u
		go func() {
			if upd.Message.IsCommand() {
				bot.HandleCmd(upd.Message)
			} else {
				bot.HandleText(upd.Message)
			}
		}()
	}
}
