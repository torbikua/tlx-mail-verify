# Mail Address Verifier

Система верификации email-адресов и анализа подлинности писем с использованием AI (Claude/OpenAI/Perplexity).

## Возможности

- **Проверка подлинности**: DKIM, SPF, DMARC валидация
- **Анализ домена**: WHOIS, возраст, DNS записи
- **Анализ IP**: Геолокация, blacklist, proxy/VPN
- **Анализ сайта**: SSL, security headers
- **AI анализ**: Глубокий анализ с вердиктом (Claude/OpenAI/Perplexity)
- **Автоматизация**: IMAP мониторинг, PDF отчёты, ответы на письма
- **Web-интерфейс**: Мониторинг и просмотр результатов

## Установка

```bash
cd /opt/mail-address-verifier
./setup.sh
```

Скрипт автоматически:
- Установит системные зависимости
- Создаст Python venv
- Установит Python пакеты
- Создаст необходимые директории

## Настройка

Отредактируйте `.env` файл:

```bash
nano .env
```

Основные параметры:

```env
# IMAP (получение писем)
IMAP_HOST=imap.example.com
IMAP_PORT=993
IMAP_USER=your-email@example.com
IMAP_PASSWORD=your-password

# SMTP (отправка отчётов)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASSWORD=your-password
SMTP_FROM=noreply@example.com

# База данных MySQL
DB_HOST=localhost
DB_PORT=3306
DB_NAME=mail_verifier
DB_USER=root
DB_PASSWORD=your-db-password

# AI провайдер: claude, openai, или perplexity
AI_PROVIDER=claude

# Claude API
ANTHROPIC_API_KEY=your-key
CLAUDE_MODEL=claude-3-5-sonnet-20241022

# OpenAI API (альтернатива)
OPENAI_API_KEY=your-key
OPENAI_MODEL=o1-preview

# Perplexity API (альтернатива с онлайн-поиском)
PERPLEXITY_API_KEY=your-key
PERPLEXITY_MODEL=sonar-pro

# Web-интерфейс
WEB_PORT=8080
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme
```

## Запуск

### Ручной запуск

```bash
./start.sh     # Запуск
./stop.sh      # Остановка
./restart.sh   # Перезапуск
./status.sh    # Статус
./logs.sh      # Просмотр логов
```

### Systemd сервис (рекомендуется)

```bash
./install-service.sh    # Установить как сервис
./uninstall-service.sh  # Удалить сервис

# Управление через systemctl
systemctl start mail-address-verifier
systemctl stop mail-address-verifier
systemctl status mail-address-verifier
journalctl -u mail-address-verifier -f
```

## Использование

1. Отправьте письмо на адрес из `IMAP_USER`
2. В теме письма добавьте `[CHECKIT]`
3. Система автоматически:
   - Обнаружит письмо
   - Проведёт все проверки
   - Отправит PDF отчёт в ответ

**Пример:**
```
To: checker@yourdomain.com
Subject: [CHECKIT] Проверить это письмо
Body: [пересланное подозрительное письмо]
```

## Логи

```bash
./logs.sh              # Следить за логами
./logs.sh -n 100       # Последние 100 строк
./logs.sh -a           # Список всех лог-файлов
```

Файлы логов:
- `logs/app_console.log` - консольный вывод
- `logs/mail_verifier_YYYYMMDD.log` - ежедневные логи

## Web-интерфейс

Доступ: `http://localhost:8080`

Логин/пароль: значения из `.env` (ADMIN_USERNAME/ADMIN_PASSWORD)

## Структура проекта

```
mail-address-verifier/
├── src/
│   ├── analyzers/     # Модули анализа (domain, ip, email, osint, website)
│   ├── services/      # Сервисы (imap, smtp, pdf, claude, openai, perplexity)
│   ├── utils/         # Утилиты (logger, database)
│   ├── web/           # Web-интерфейс (Flask)
│   └── main.py        # Точка входа
├── config/            # Конфигурация
├── database/          # SQL схемы
├── logs/              # Логи приложения
├── data/
│   ├── attachments/   # Сохранённые письма
│   └── reports/       # PDF отчёты
├── scripts/           # Вспомогательные скрипты
├── fonts/             # Шрифты для PDF
├── .env               # Конфигурация (не в git)
├── .env.example       # Шаблон конфигурации
├── requirements.txt   # Python зависимости
├── setup.sh           # Установка
├── start.sh           # Запуск
├── stop.sh            # Остановка
├── restart.sh         # Перезапуск
├── status.sh          # Статус
└── logs.sh            # Просмотр логов
```

## Вспомогательные скрипты

В папке `scripts/`:
- `clear_database.py` - очистка базы данных
- `create_admin_user.py` - создание админа
- `regenerate_pdf.py` - перегенерация PDF

## Docker (альтернатива)

```bash
docker-compose up -d
docker-compose logs -f app
```

## Troubleshooting

**Не подключается к IMAP:**
```bash
./logs.sh | grep -i imap
```

**Ошибка AI API:**
```bash
./logs.sh | grep -i "claude\|openai\|perplexity"
```

**Не отправляются отчёты:**
```bash
./logs.sh | grep -i smtp
```
