# PaperSecBot
Бот, который вам поможет писать отчет по пентостику

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

# 2. Инициализируйте go-модуль и подтяните зависимости
go mod init papersecbot
go mod tidy

# 3. Установите переменные окружения
export TELEGRAM_BOT_TOKEN=<bot_token>
export OPENAI_API_KEY=<optional_openai_key>
export OPENAI_MODEL=gpt-4o  # или gpt-4o-mini

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
Telegram → PaperSecBot.go → (опц.) OpenAI GPT-4o → Markdown-ответ
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


