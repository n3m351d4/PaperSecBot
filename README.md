# PaperSecBot
Бот, который вам поможет писать отчет по пентесту

**PaperSecBot** — минималистичный Telegram-бот на Go, который помогает пентестерам
быстро оформлять отчёт об уязвимости. Бот принимает краткое текстовое описание бага,
отправляет его в OpenAI GPT-4o для обогащения техническими деталями
(CVSS, PoC, рекомендации) и выдаёт готовый Markdown-блок.

## Возможности

- 💬 Чат-интерфейс в Telegram (`/bug`)
- 🧠 Интеграция с OpenAI GPT-4o (при наличии `OPENAI_API_KEY`)
- 📑 Автоматическое заполнение:
  - Severity (High/Medium/Low/Critical)
  - CVSS балл и вектор
  - Затронутые активы
  - Краткое техническое описание (RU)
  - Подсказки для скриншотов / PoC
  - **Рекомендации** с ссылками PortSwigger и Acunetix  
- 🔒 Безопасные дефолты — если ключ OpenAI не указан, бот всё равно работает,
  возвращая базовый шаблон

## Быстрый старт

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/n3m351d4/PaperSecBot
cd PaperSecBot

# 2. Подтяните зависимости
go mod tidy

# 3. Установите переменные окружения
export TELEGRAM_BOT_TOKEN=<bot_token>
export OPENAI_API_KEY=<optional_openai_key>
export OPENAI_MODEL=gpt-4o  # или gpt-4o-mini
export OPENAI_MAX_TOKENS=10000  # опц. лимит токенов

# 4. Запустите
go run .
```

## Переменные окружения

| Переменная | Обязательно | Описание |
| ---------- | ----------- | -------------------------------------------- |
| `TELEGRAM_BOT_TOKEN` | ✅ | Токен Telegram-бота |
| `OPENAI_API_KEY` | ❌ | (опц.) Ключ OpenAI API (GPT-4o). Без него бот вернёт шаблон без обогащения |
| `OPENAI_MODEL` | ❌ | (опц.) Имя модели OpenAI, например `gpt-4o` или `gpt-4o-mini` |
| `OPENAI_MAX_TOKENS` | ❌ | (опц.) Максимальное число токенов в ответе (по умолчанию 10000) |


Ключи OpenAI можно купить тут -> @gpt_keys_shop_bot

## Использование

1. Напишите боту `/start` — получите краткую справку.
2. Команда `/bug` запускает режим ввода.
3. Отправьте **одной строкой**:

   * URL/ы;
   * в чём суть бага;
   * при желании — выдержку из Burp/HTTP-запрос.
4. Бот вернёт готовый фрагмент отчёта, который можно вставить
   в Pentest-Report или Wiki.

### Пример

```
/bug
на портале example.com обнаружен IDOR: /id=1 → /id=2 — выдаёт данные другого пользователя
```

Ответ:

```
**[High] Insecure Direct Object Reference (IDOR)**
**CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Затронутые активы:** example.com

**Описание:**
...

*Скриншоты: запрос /id=1 и /id=2, сравнение JSON-ответов*

**Рекомендации:**
...
```

## Архитектура

```
Telegram → main.go → (опц.) OpenAI GPT-4o → Markdown-ответ
```

* **tg-бот**: `github.com/go-telegram-bot-api/telegram-bot-api/v5`
* **LLM-клиент**: `github.com/sashabaranov/go-openai`

## Разработка

```bash
# Тестовый запуск без OpenAI
unset OPENAI_API_KEY
go run .

# Сборка бинаря
go build -o papersecbot .
```
Here is the English translation:

---

# PaperSecBot

A bot to help you write penetration testing reports

**PaperSecBot** is a minimalist Telegram bot written in Go that helps pentesters quickly format vulnerability reports. The bot accepts a short text description of a bug, sends it to OpenAI GPT-4o to enrich it with technical details (CVSS, PoC, recommendations), and returns a ready-to-use Markdown block.

## Features

* 💬 Chat interface in Telegram (`/bug`)
* 🧠 Integration with OpenAI GPT-4o (requires `OPENAI_API_KEY`)
* 📑 Auto-filled fields:

  * Severity (High/Medium/Low/Critical)
  * CVSS score and vector
  * Affected assets
  * Brief technical description (in Russian)
  * Screenshot / PoC hints
  * **Recommendations** with PortSwigger and Acunetix links
* 🔒 Secure defaults — if no OpenAI key is provided, the bot still works and returns a basic template

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/n3m351d4/PaperSecBot
cd PaperSecBot

# 2. Fetch dependencies
go mod tidy

# 3. Set environment variables
export TELEGRAM_BOT_TOKEN=<bot_token>
export OPENAI_API_KEY=<optional_openai_key>
export OPENAI_MODEL=gpt-4o  # or gpt-4o-mini
export OPENAI_MAX_TOKENS=10000  # optional token limit

# 4. Run
go run .
```

## Environment Variables

| Variable             | Required | Description                                                                |
| -------------------- | -------- | -------------------------------------------------------------------------- |
| `TELEGRAM_BOT_TOKEN` | ✅        | Telegram bot token                                                         |
| `OPENAI_API_KEY`     | ❌        | (optional) OpenAI API key (GPT-4o). If not set, basic template is returned |
| `OPENAI_MODEL`       | ❌        | (optional) OpenAI model name, e.g. `gpt-4o` or `gpt-4o-mini`               |
| `OPENAI_MAX_TOKENS`  | ❌        | (optional) Max token limit for OpenAI response (default 10000)             |

You can buy OpenAI keys here → @gpt\_keys\_shop\_bot

## Usage

1. Send `/start` to the bot to get a short help message.
2. Use `/bug` to activate input mode.
3. Send a **single-line message** with:

   * URL(s);
   * Bug summary;
   * Optional: snippet from Burp/HTTP request.
4. The bot will return a ready-to-paste report snippet for your Pentest Report or Wiki.

### Example

```
/bug
example.com has IDOR: /id=1 → /id=2 reveals another user’s data
```

Response:

```
**[High] Insecure Direct Object Reference (IDOR)**
**CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Affected assets:** example.com

**Description:**
...

*Screenshots: request to /id=1 and /id=2, compare JSON responses*

**Recommendations:**
...
```

## Architecture

```
Telegram → main.go → (optional) OpenAI GPT-4o → Markdown response
```

* **Telegram bot lib**: `github.com/go-telegram-bot-api/telegram-bot-api/v5`
* **LLM client**: `github.com/sashabaranov/go-openai`

## Development

```bash
# Test run without OpenAI
unset OPENAI_API_KEY
go run .

# Build binary
go build -o papersecbot .
```

