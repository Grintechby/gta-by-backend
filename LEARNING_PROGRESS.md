# Прогресс обучения - Интернет-магазин автозапчастей

## Этап 1: Настройка инфраструктуры ✅ ЗАВЕРШЕН

### Что изучено:
1. **Nest.js структура**
   - Модули, контроллеры, сервисы
   - Dependency Injection
   - Lifecycle hooks (OnModuleInit, OnModuleDestroy)

2. **PostgreSQL в Docker**
   - Настройка через docker-compose.yml
   - Понимание контейнеризации
   - Работа с volumes

3. **Prisma 7**
   - Настройка Prisma с adapter (@prisma/adapter-pg)
   - Создание моделей в schema.prisma
   - Создание и применение миграций
   - Команды: `prisma migrate dev`, `prisma generate`

4. **Swagger документация**
   - Настройка Swagger в Nest.js
   - Использование декораторов (@ApiTags)
   - Группировка эндпоинтов по тегам

5. **Git и версионирование**
   - Правильные коммиты
   - Что коммитить, а что нет

### Структура проекта:
```
gta-by-backend/
├── src/
│   ├── prisma/
│   │   ├── prisma.service.ts    # PrismaService с adapter
│   │   └── prisma.module.ts      # Глобальный модуль
│   ├── users/
│   │   ├── users.service.ts      # Бизнес-логика
│   │   ├── users.controller.ts   # HTTP эндпоинты
│   │   └── users.module.ts        # Модуль пользователей
│   ├── app.module.ts
│   └── main.ts                    # Настройка Swagger
├── prisma/
│   ├── schema.prisma              # Схема БД
│   └── migrations/                # Миграции
├── docker-compose.yml              # PostgreSQL
└── prisma.config.ts               # Конфигурация Prisma 7
```

### Важные концепции:
- **@Injectable()** - делает класс доступным для DI
- **@Global()** - делает модуль доступным везде
- **exports** - определяет, что модуль предоставляет другим
- **implements OnModuleInit** - контракт на реализацию lifecycle hooks
- **Prisma adapter** - новый подход в Prisma 7 для подключения к БД

---

## Этап 2: Backend - Базовая структура и аутентификация (часть 1) ✅ ЗАВЕРШЕН

### Что изучено:
1. **PrismaService**
   - Настройка с adapter для Prisma 7
   - Lifecycle hooks для подключения/отключения
   - Глобальный модуль

2. **UsersService**
   - Методы: createUser, findByEmail, findById
   - Работа с Prisma Client
   - Типизация (Prisma.UserCreateInput, User)

3. **UsersController**
   - Эндпоинты: POST /users, GET /users/:id, GET /users/email/:email
   - Использование @Body(), @Param()
   - Тонкий контроллер (бизнес-логика в сервисе)

4. **Обработка ошибок**
   - ConflictException для дубликатов (P2002)
   - NotFoundException для отсутствующих записей
   - InternalServerErrorException для критических ошибок БД
   - Разделение ответственности (сервис vs контроллер)

### Важные концепции:
- **Обработка ошибок Prisma** - проверка error.code === 'P2002'
- **HTTP исключения** - автоматически преобразуются в HTTP ответы
- **throw прерывает выполнение** - метод ничего не возвращает при исключении
- **Разделение ответственности** - сервис обрабатывает ошибки, контроллер только маршрутизация

### Текущая модель User:
```prisma
model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  name      String?
  role      String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

---

## Следующие шаги:

### Этап 2 (продолжение): Модуль аутентификации
1. Установить пакеты: bcrypt, @nestjs/jwt, @nestjs/passport, passport, passport-jwt
2. Создать модуль Auth
3. Реализовать регистрацию (хеширование пароля)
4. Реализовать логин (JWT токены)
5. Настроить Guards для защиты роутов
6. Создать DTO для валидации

### Этап 3: Каталог товаров
- Модели Category и Product
- CRUD операции
- Фильтрация и поиск

---

## Команды для восстановления проекта:

```bash
# 1. Клонировать репозиторий
git clone <your-repo-url>
cd gta-by-backend

# 2. Установить зависимости
npm install

# 3. Запустить PostgreSQL
docker-compose up -d

# 4. Применить миграции
npm run prisma:migrate

# 5. Сгенерировать Prisma Client
npm run prisma:generate

# 6. Запустить приложение
npm run start:dev
```

---

## Важные файлы для проверки:

- `.env` - переменные окружения (создать заново из .env.example)
- `docker-compose.yml` - настройка PostgreSQL
- `prisma/schema.prisma` - схема БД
- `package.json` - зависимости проекта

---

## Полезные ссылки:

- [Nest.js документация](https://docs.nestjs.com)
- [Prisma документация](https://www.prisma.io/docs)
- [Nest.js + Prisma рецепт](https://docs.nestjs.com/recipes/prisma)

---

## Заметки:

- Используем Prisma 7 с adapter (@prisma/adapter-pg)
- Алиасы путей настроены в tsconfig.json
- Swagger доступен по адресу /docs (или /api)
- Все ошибки обрабатываются в сервисах, контроллеры тонкие

