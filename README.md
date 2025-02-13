# API Generator

Простой, но функциональный генератор API, созданный с учётом расширенных мер безопасности. Позволяет быстро развернуть RESTful-сервис с регистрацией пользователей, аутентификацией через JWT, CRUD-операциями по сущностям, а также встроенными механизмами защиты от атак.

## Основные возможности

- 🔐 **JWT-аутентификация**: Поддержка создания и проверки токенов (access и refresh).
- 🛡️ **Расширенная безопасность**:
  - Хранение секретных ключей в переменных окружения.
  - Ограничение частоты запросов (Rate Limiting).
  - Проверка на CSRF-токен.
  - Мягкое удаление (soft delete) ресурсов.
  - Проверка IP-адресов на блокировку (Blacklist).
  - Логирование подозрительных запросов.
- 📦 **Управление ресурсами**: Создание, чтение, обновление и удаление (CRUD) с помощью универсального генератора API, который работает с моделями базы данных.
- ⚡ **Оптимизированая работа с БД**: Использование SQLAlchemy и поддержка миграций с Flask-Migrate.
- ✉️ **Уведомления**: Возможность отправки приветственных писем пользователям.
- ⚙️ **Гибкая настройка**: Отключение/включение режимов обслуживания, планирование обслуживания, кастомизация роутов.

---

## Установка и настройка

### Установка зависимостей

Вам понадобится Python 3.8 или выше. Установите необходимые пакеты:
```bash
pip install flask flask-sqlalchemy flask-migrate flask-bcrypt flask-jwt-extended flask-limiter
```
*В зависимости от выбранной среды могут потребоваться дополнительные зависимости.*

### Переменные окружения

Создайте (или обновите) файл .env и пропишите переменные для безопасности:

```py
APP_SECRET_KEY="Ваш случайный секретный ключ" JWT_SECRET_KEY="Ключ для JWT-токенов" DATABASE_URI="sqlite:///my_secure_app.db"
```

- **APP_SECRET_KEY** – ключ, используемый Flask-приложением для сессий, CSRF и т. д.
- **JWT_SECRET_KEY** – ключ для подписи JWT-токенов (access и refresh).
- **DATABASE_URI** – строка подключения к вашей базе данных.

При деплое на сервер прежде всего заменяйте эти переменные на значения из среды (например, через Docker или конфигурацию CI/CD).

---

## Миграции базы данных

1. Инициализируйте директорию для миграций:
   ```bash
   flask db init
   ```

2. Создайте первую миграцию:
   ```bash
   flask db migrate -m "Initial migration"
   ```

3. Примените миграции к базе:
   ```bash
   flask db upgrade
   ```

---

## Запуск приложения

Запустите ваше Flask-приложение (убедитесь, что все необходимые переменные окружения заданы):
```bash
flask run
```
Приложение обычно доступно по адресу http://127.0.0.1:5000, если не указано иное.

**Важно**: В окружении рекомендуется:
- Запускать в режиме debug=False.
- Использовать выделенный сервер (например, gunicorn или uwsgi) за Nginx.
- Активировать дополнительные механизмы безопасности (HTTPS).

---

## Примеры запросов

### Регистрация
```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "password": "strongpassword", "email": "newuser@example.com"}'
```
### Вход в систему (получение JWT)
```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "password": "strongpassword"}'
```
В ответ приходит `access_token` и `refresh_token`, которые применяются для аутентифицированных запросов.

### CRUD для ресурса (пример)

1. **Создать ресурс** (POST)
   ```bash
   curl -X POST http://localhost:5000/api/resource/ \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <ACCESS_TOKEN>" \
     -H "X-CSRF-Token: SECURE_CSRF_TOKEN_PLACEHOLDER" \
     -d '{"name":"Resource A", "description":"Описание ресурса A"}'
   ```
2. **Получить список** (GET)
   ```bash
   curl http://localhost:5000/api/resource/ \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
   ```
3. **Обновить ресурс** (PUT/PATCH)
   ```bash
   curl -X PUT http://localhost:5000/api/resource/1 \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <ACCESS_TOKEN>" \
     -H "X-CSRF-Token: SECURE_CSRF_TOKEN_PLACEHOLDER" \
     -d '{"description":"Новое описание ресурса"}'
   ```
4. **Удалить ресурс (soft-delete)** (DELETE)
   ```bash
   curl -X DELETE http://localhost:5000/api/resource/1 \
     -H "Authorization: Bearer <ACCESS_TOKEN>" \
     -H "X-CSRF-Token: SECURE_CSRF_TOKEN_PLACEHOLDER"
   ```

---

## Экспорт
Для демонстрационных целей реализована возможность экспортировать ресурсы, привязанные к пользователю:
```bash
curl -X GET http://localhost:5000/export \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -o resources.json
```
*Возможны варианты форматирования (JSON, CSV), зависящие от конкретной реализации.*

---

## Структура (примерная)
  ├── main.py 

  ├── models.py # Модели (User, Resource, ...) 

  ├── .env # Переменные окружения

  ├── requirements.txt # Зависимости проекта 

  └── migrations/ # Папка с миграциями


---

## Рекомендации по безопасности

- Всегда используйте индивидуальные секретные ключи различной длины и сложности.
- Ограничивайте число запросов с одного IP (установлено по умолчанию через Flask-Limiter).
- Храните пароли в зашифрованном виде (bcrypt, Argon2 и т. п.).
- При работе в реальном окружении обязательно используйте HTTPS.
- Регулярно создавайте резервные копии (backup) базы данных.
- Добавляйте защиту от CSRF там, где это уместно, и проверяйте корректный токен в заголовках.

---

## Лицензия
Проект распространяется по лицензии MIT. См. файл [LICENSE](LICENSE) для подробностей.
