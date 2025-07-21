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
	telegramBot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatalf("bot init: %v", err)
	}
	log.Printf("Authorized as %s", telegramBot.Self.UserName)

	var openAIClient openaiutil.AIClient
	if k := os.Getenv("OPENAI_API_KEY"); k != "" {
		openAIClient = openai.NewClient(k)
	}

	bot := telegram.New(telegramBot, openAIClient)
	updates := telegramBot.GetUpdatesChan(tgbotapi.UpdateConfig{Timeout: 60})
	for update := range updates {
		if update.Message == nil {
			continue
		}
		go func(u tgbotapi.Update) {
			if u.Message.IsCommand() {
				log.Printf("command from %d: %s", u.Message.Chat.ID, u.Message.Text)
				bot.HandleCmd(u.Message)
			} else {
				log.Printf("message from %d: %q", u.Message.Chat.ID, u.Message.Text)
				bot.HandleText(u.Message)
			}
		}(update)
	}
}
