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
  password  String
  role      String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

---

## Этап 2 (продолжение): Модуль аутентификации - DTO ✅ ЗАВЕРШЕН

### Что изучено:

1. **DTO (Data Transfer Objects)**
   - Созданы `RegisterDto` и `LoginDto` для валидации входящих данных
   - Использование `class-validator` для автоматической валидации
   - Использование `@ApiProperty` для Swagger документации

2. **Декораторы валидации:**
   - `@IsEmail()` - проверка формата email
   - `@IsString()` - проверка типа строки
   - `@MinLength(6)` - проверка минимальной длины
   - `@IsOptional()` - необязательное поле
   - `@ApiProperty()` - описание для Swagger

### Структура DTO:

**RegisterDto** (`src/auth/dto/register.dto.ts`):
- `email` - обязательное поле, валидный email
- `password` - обязательное поле, минимум 6 символов
- `name` - необязательное поле

**LoginDto** (`src/auth/dto/login.dto.ts`):
- `email` - обязательное поле, валидный email
- `password` - обязательное поле

### Важные концепции:

- **DTO** - классы для валидации входящих данных от клиента
- **class-validator** - автоматически проверяет данные по декораторам
- Если валидация не проходит - возвращается HTTP 400 (Bad Request)
- **@ApiProperty** - делает поля видимыми в Swagger документации
- DTO используются в контроллерах через `@Body()` декоратор

### Как это работает:

1. Клиент отправляет данные (например, JSON)
2. Nest.js автоматически проверяет данные по правилам в DTO
3. Если данные неверные - возвращается ошибка 400
4. Если данные верные - они передаются в сервис

---

## Этап 2 (продолжение): Модуль аутентификации - AuthService ✅ ЗАВЕРШЕН

### Что изучено:

1. **AuthService** (`src/auth/auth.service.ts`)
   - Метод `register()` - регистрация пользователя с хешированием пароля
   - Метод `login()` - вход пользователя с проверкой пароля и генерацией JWT

2. **Хеширование паролей (bcryptjs)**
   - `bcrypt.hash(password, 10)` - хеширование пароля (10 раундов)
   - `bcrypt.compare(plainPassword, hashedPassword)` - сравнение пароля с хешем
   - Пароли НИКОГДА не хранятся в открытом виде в БД

3. **JWT токены**
   - `jwtService.signAsync(payload)` - генерация JWT токена
   - Payload содержит: `{ sub: userId, email: userEmail }`
   - `sub` - стандартное поле для ID пользователя в JWT

4. **Dependency Injection**
   - `UsersService` - для работы с пользователями
   - `JwtService` - для генерации токенов
   - Передаются через конструктор

### Методы AuthService:

**register(registerDto: RegisterDto):**
1. Хеширует пароль с помощью `bcrypt.hash()`
2. Создаёт пользователя через `UsersService.createUser()`
3. Генерирует JWT токен
4. Возвращает данные пользователя (БЕЗ пароля) и токен

**login(loginDto: LoginDto):**
1. Находит пользователя по email через `UsersService.findByEmail()`
2. Сравнивает пароль с хешем через `bcrypt.compare()`
3. Если пароль неверный - выбрасывает `UnauthorizedException`
4. Генерирует JWT токен
5. Возвращает данные пользователя и токен

### Важные концепции:

- **Хеширование паролей** - односторонняя функция, нельзя восстановить оригинал
- **bcrypt** - алгоритм хеширования с "солью" (salt) для безопасности
- **JWT (JSON Web Token)** - токен для аутентификации без хранения сессий
- **Payload JWT** - данные внутри токена (обычно ID и email пользователя)
- **UnauthorizedException** - HTTP 401 (неавторизован), используется при неверных credentials
- **Безопасность** - пароль никогда не возвращается в ответе API

### Шпаргалка по bcryptjs:

```typescript
import * as bcrypt from 'bcryptjs';

// Хеширование пароля (при регистрации)
const hashedPassword = await bcrypt.hash('plainPassword', 10);
// 10 - количество раундов (больше = безопаснее, но медленнее)

// Сравнение пароля (при логине)
const isValid = await bcrypt.compare('plainPassword', hashedPassword);
// Возвращает true/false
```

### Шпаргалка по JWT:

```typescript
import { JwtService } from '@nestjs/jwt';

// Генерация токена
const payload = { sub: userId, email: userEmail };
const token = await jwtService.signAsync(payload);

// Payload будет закодирован в токене
// Токен можно декодировать (но не подделать без секретного ключа)
```

---

## Этап 2 (продолжение): Модуль аутентификации - JWT Strategy ✅ ЗАВЕРШЕН

### Что изучено:

1. **JWT Strategy** (`src/auth/strategies/jwt.strategy.ts`)
   - Стратегия Passport.js для проверки JWT токенов
   - Извлекает токен из заголовка запроса
   - Проверяет валидность токена
   - Находит пользователя в БД и возвращает его данные

2. **Passport.js стратегии**
   - `PassportStrategy` - базовый класс для стратегий в Nest.js
   - `Strategy` - JWT стратегия из `passport-jwt`
   - `ExtractJwt` - утилиты для извлечения токена из запроса

3. **Метод validate()**
   - Вызывается автоматически после проверки токена
   - Получает payload (данные из токена)
   - Находит пользователя в БД
   - Возвращает данные пользователя (доступны в контроллере через `request.user`)

### Структура JWT Strategy:

**Интерфейс JwtPayload:**
```typescript
export interface JwtPayload {
  sub: number;  // ID пользователя (стандартное поле JWT)
  email: string;
}
```

**Класс JwtStrategy:**
```typescript
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly usersService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // ↑ Извлекает токен из заголовка: Authorization: Bearer <token>
      
      ignoreExpiration: false,
      // ↑ Проверяет срок действия токена
      
      secretOrKey: process.env.JWT_SECRET || 'fallback-key',
      // ↑ Секретный ключ для проверки подписи
    });
  }

  async validate(payload: JwtPayload) {
    // Находим пользователя по ID из токена
    const user = await this.usersService.findById(payload.sub);
    
    // Если пользователь не найден - ошибка
    if (!user) {
      throw new UnauthorizedException();
    }
    
    // Возвращаем данные (будут в request.user в контроллере)
    return { id: user.id, email: user.email, role: user.role };
  }
}
```

### Важные концепции:

- **Passport Strategy** - паттерн для аутентификации в Node.js
- **JWT Strategy** - конкретная реализация для проверки JWT токенов
- **ExtractJwt.fromAuthHeaderAsBearerToken()** - извлекает токен из заголовка `Authorization: Bearer <token>`
- **validate()** - вызывается автоматически после успешной проверки токена
- **request.user** - данные, возвращённые из `validate()`, доступны в контроллере
- **JWT_SECRET** - секретный ключ для подписи/проверки токенов (хранится в `.env`)

### Как это работает:

1. **Клиент отправляет запрос** с заголовком: `Authorization: Bearer <token>`
2. **Passport извлекает токен** из заголовка через `ExtractJwt.fromAuthHeaderAsBearerToken()`
3. **Проверяет токен:**
   - Проверяет подпись с помощью `JWT_SECRET`
   - Проверяет срок действия (если `ignoreExpiration: false`)
4. **Если токен валиден** - вызывает метод `validate(payload)`
5. **validate() находит пользователя** в БД по `payload.sub` (ID пользователя)
6. **Возвращает данные пользователя** - они попадают в `request.user` в контроллере
7. **Если токен невалиден** - возвращается HTTP 401 (Unauthorized)

### Шпаргалка по JWT_SECRET:

**Требования к секретному ключу:**
- Минимум 32 символа (рекомендуется 64+)
- Случайный и непредсказуемый
- Содержит буквы, цифры, специальные символы
- Уникальный для каждого проекта
- Хранится в `.env` (не коммитится в Git)

**Генерация ключа:**
```bash
# Node.js
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# OpenSSL (если установлен)
openssl rand -base64 64
```

**Использование в .env:**
```env
JWT_SECRET="ваш-сгенерированный-секретный-ключ-минимум-32-символа"
```

### Шпаргалка по ExtractJwt:

```typescript
import { ExtractJwt } from 'passport-jwt';

// Из заголовка Authorization: Bearer <token>
ExtractJwt.fromAuthHeaderAsBearerToken()

// Из query параметра: ?token=xxx
ExtractJwt.fromUrlQueryParameter('token')

// Из cookie
ExtractJwt.fromAuthHeaderWithScheme('Bearer')

// Кастомная функция
ExtractJwt.fromHeader('custom-header')
```

### Важные моменты:

- **Стратегия регистрируется в модуле** (будет в AuthModule)
- **Данные из validate()** доступны в контроллере через `request.user`
- **Если validate() выбрасывает исключение** - запрос отклоняется с HTTP 401
- **Токен проверяется автоматически** - не нужно вызывать validate() вручную

---

## Этап 2 (продолжение): Модуль аутентификации - JWT Guard ✅ ЗАВЕРШЕН

### Что изучено:

1. **Guards в Nest.js**
   - Классы, которые выполняются ПЕРЕД контроллером
   - Решают, разрешить ли запрос
   - Могут выбрасывать исключения для отклонения запроса

2. **JWT Auth Guard** (`src/auth/guards/jwt-auth.guard.ts`)
   - Защищает роуты от неавторизованных запросов
   - Использует JWT Strategy для проверки токена
   - Автоматически проверяет наличие и валидность токена

3. **Жизненный цикл запроса в Nest.js:**
   ```
   Middleware → Guards → Interceptors (до) → Pipes → Controller → Service → Interceptors (после) → Exception Filters
   ```

### Структура JWT Guard:

```typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
```

**Объяснение:**
- `AuthGuard('jwt')` - использует стратегию с именем 'jwt'
- Имя 'jwt' должно совпадать с именем стратегии в модуле
- `@Injectable()` - делает класс доступным для Dependency Injection

### Как использовать Guard:

**Вариант 1: На уровне метода (конкретный роут)**
```typescript
@Controller('users')
export class UsersController {
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req) {
    return req.user; // Данные из JWT Strategy validate()
  }
}
```

**Вариант 2: На уровне контроллера (все роуты)**
```typescript
@Controller('users')
@UseGuards(JwtAuthGuard) // Защищает все роуты
export class UsersController {
  @Get('profile')
  getProfile(@Req() req) {
    return req.user;
  }
}
```

**Вариант 3: Публичный роут (без защиты)**
```typescript
@Controller('auth')
export class AuthController {
  @Post('register')
  register() {
    // Публичный роут - не требует токена
  }

  @UseGuards(JwtAuthGuard) // Только этот роут защищён
  @Get('me')
  getMe(@Req() req) {
    return req.user;
  }
}
```

### Важные концепции:

- **Guards** - выполняются перед контроллером, могут остановить выполнение
- **@UseGuards()** - декоратор для применения Guard к роуту
- **AuthGuard('jwt')** - использует Passport стратегию с именем 'jwt'
- **request.user** - данные, возвращённые из `validate()` JWT Strategy
- **Автоматическая проверка** - Guard автоматически проверяет токен, не нужно делать это вручную
- **HTTP 401** - если токен невалиден, автоматически возвращается Unauthorized

### Как это работает:

1. **Guard применяется к роуту** через `@UseGuards(JwtAuthGuard)`
2. **При запросе Guard:**
   - Извлекает токен из заголовка (через JWT Strategy)
   - Проверяет токен (через JWT Strategy)
   - Вызывает `validate()` из JWT Strategy
3. **Если токен валиден:**
   - Пропускает запрос дальше
   - Данные пользователя доступны в `request.user`
4. **Если токен невалиден:**
   - Выбрасывает `UnauthorizedException`
   - Возвращает HTTP 401
   - Запрос не доходит до контроллера

### Шпаргалка по Guards:

```typescript
// Импорт
import { UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'auth/guards/jwt-auth.guard';

// Применение на уровне метода
@UseGuards(JwtAuthGuard)
@Get('protected-route')
getProtected() { ... }

// Применение на уровне контроллера
@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController { ... }

// Доступ к данным пользователя
@Get('profile')
getProfile(@Req() req) {
  const user = req.user; // Данные из JWT Strategy validate()
  return user;
}
```

---

## Этап 2 (продолжение): Модуль аутентификации - AuthController и декораторы ✅ ЗАВЕРШЕН

### Что изучено:

1. **AuthController** (`src/auth/auth.controller.ts`)
   - Эндпоинты для регистрации, входа и получения текущего пользователя
   - Использование декораторов Swagger для документации
   - Применение Guards для защиты роутов

2. **Кастомный декоратор @CurrentUser()**
   - Создание параметр-декоратора через `createParamDecorator`
   - Упрощение доступа к данным пользователя
   - Типизация возвращаемого значения

3. **Типизация Request в Express**
   - Расширение интерфейса `Request` через `declare module`
   - Добавление свойства `user` в типы Express

4. **Общие типы**
   - Вынос типов в отдельные файлы (`types/user.types.ts`)
   - Переиспользование типов в разных местах
   - Единый источник истины для типов

### Структура AuthController:

**Эндпоинты:**
- `POST /auth/register` - регистрация (публичный)
- `POST /auth/login` - вход (публичный)
- `GET /auth/me` - получение текущего пользователя (защищённый)

**Пример:**
```typescript
@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Регистрация нового пользователя' })
  @ApiResponse({ status: 201, description: 'Пользователь зарегистрирован' })
  async register(@Body() registerDto: RegisterDto) {
    return await this.authService.register(registerDto);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  getMe(@CurrentUser() user: CurrentUserType) {
    return { user };
  }
}
```

### Декоратор @CurrentUser:

**Создание декоратора** (`src/auth/decorators/current-user.decorator.ts`):
```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { CurrentUserType } from 'types/user.types';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): CurrentUserType => {
    const request = ctx.switchToHttp().getRequest<Request>();
    
    if (!request?.user) {
      throw new Error('User not found');
    }
    
    return request.user;
  },
);
```

**Использование:**
```typescript
@Get('me')
@UseGuards(JwtAuthGuard)
getMe(@CurrentUser() user: CurrentUserType) {
  return { user };
}
```

### Типизация Request:

**Расширение интерфейса Express** (`src/types/express.d.ts`):
```typescript
import { CurrentUserType } from './user.types';

declare module 'express' {
  export interface Request {
    user?: CurrentUserType;
  }
}
```

**Объяснение:**
- `declare module 'express'` - расширяет модуль Express
- Добавляет свойство `user` в интерфейс `Request`
- Использует общий тип `CurrentUserType`

### Общие типы:

**Создание типа** (`src/types/user.types.ts`):
```typescript
export interface CurrentUserType {
  id: number;
  email: string;
  name: string | null;
  role: string;
}
```

**Использование везде:**
- В `express.d.ts` - для типизации `Request.user`
- В декораторе `@CurrentUser` - для возвращаемого типа
- В контроллере - для типизации параметра

### Важные концепции:

- **@ApiOperation** - описание эндпоинта в Swagger
- **@ApiResponse** - описание возможных ответов эндпоинта
- **createParamDecorator** - создание кастомного параметр-декоратора
- **ExecutionContext** - контекст выполнения (HTTP запрос)
- **declare module** - расширение существующих модулей/типов
- **import type** - импорт только типов (не попадает в JavaScript)
- **Единый источник истины** - тип определён в одном месте, используется везде

### Шпаргалка по декораторам Swagger:

```typescript
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('auth') // Группировка эндпоинтов
@Controller('auth')
export class AuthController {
  @Post('register')
  @ApiOperation({ summary: 'Краткое описание' })
  @ApiResponse({ 
    status: 201, 
    description: 'Описание ответа' 
  })
  async register() { ... }
}
```

### Шпаргалка по кастомным декораторам:

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

// Создание декоратора
export const MyDecorator = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    // data - параметры, переданные в декоратор
    // ctx - контекст выполнения
    return request.something;
  },
);

// Использование
@Get('route')
getRoute(@MyDecorator() value) {
  return value;
}
```

### Шпаргалка по типизации:

```typescript
// Расширение интерфейса
declare module 'express' {
  export interface Request {
    customProperty?: MyType;
  }
}

// Импорт типа (для декорированных параметров)
import type { MyType } from './types';

// Использование
@Get('route')
getRoute(@MyDecorator() value: MyType) {
  return value;
}
```

### Важные моменты:

- **import type** - обязательно для типов в декорированных параметрах (при `isolatedModules`)
- **declare module** - расширяет существующие типы без их изменения
- **createParamDecorator** - стандартный способ создания кастомных декораторов
- **ExecutionContext** - предоставляет доступ к HTTP запросу/ответу
- **Единый тип** - лучше вынести в общий файл для переиспользования

---

## Этап 2 (продолжение): Модуль аутентификации - AuthModule ✅ ЗАВЕРШЕН

### Что изучено:

1. **AuthModule** (`src/auth/auth.module.ts`)
   - Объединяет все компоненты аутентификации
   - Настраивает JWT модуль с секретом и временем жизни токена
   - Регистрирует стратегию, сервис и контроллер

2. **Настройка JwtModule**
   - `JwtModule.register()` - регистрация с конфигурацией
   - `secret` - секретный ключ для подписи токенов
   - `signOptions.expiresIn` - время жизни токена

3. **Регистрация в AppModule**
   - Добавление `AuthModule` в `imports` корневого модуля
   - Модуль становится доступным во всём приложении

### Структура AuthModule:

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UsersModule } from 'users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    UsersModule,        // Для UsersService
    PassportModule,     // Для Passport стратегий
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'fallback-key',
      signOptions: { expiresIn: '7d' }, // Время жизни токена
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [AuthService], // Экспортируем для использования в других модулях
})
export class AuthModule {}
```

### Регистрация в AppModule:

```typescript
import { AuthModule } from 'auth/auth.module';

@Module({
  imports: [
    PrismaModule,
    UsersModule,
    AuthModule, // Добавляем модуль аутентификации
  ],
  // ...
})
export class AppModule {}
```

### Важные концепции:

- **Модули в Nest.js** - объединяют связанные компоненты (контроллеры, сервисы, провайдеры)
- **JwtModule.register()** - настройка JWT с секретом и опциями
- **PassportModule** - необходим для работы Passport стратегий
- **Providers** - сервисы и стратегии, которые используются в модуле
- **Exports** - что модуль предоставляет другим модулям
- **Имя стратегии** - автоматически регистрируется как 'jwt' (используется в `AuthGuard('jwt')`)

### Настройка JWT:

**Параметры JwtModule.register():**
- `secret` - секретный ключ для подписи/проверки токенов
- `signOptions.expiresIn` - время жизни токена:
  - `'24h'` - 24 часа
  - `'7d'` - 7 дней
  - `'1h'` - 1 час
  - `'30m'` - 30 минут

**Примеры:**
```typescript
JwtModule.register({
  secret: process.env.JWT_SECRET || 'fallback-key',
  signOptions: { expiresIn: '24h' },
}),

// Или с переменной окружения
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '7d';
JwtModule.register({
  secret: process.env.JWT_SECRET || 'fallback-key',
  signOptions: { expiresIn: jwtExpiresIn },
}),
```

### Шпаргалка по модулям:

```typescript
@Module({
  imports: [
    // Модули, которые нужны этому модулю
    OtherModule,
  ],
  controllers: [
    // Контроллеры этого модуля
    MyController,
  ],
  providers: [
    // Сервисы, стратегии и другие провайдеры
    MyService,
    MyStrategy,
  ],
  exports: [
    // Что предоставляем другим модулям
    MyService,
  ],
})
export class MyModule {}
```

### Важные моменты:

- **Импорты** - модули, от которых зависит текущий модуль
- **Контроллеры** - HTTP эндпоинты
- **Провайдеры** - сервисы, стратегии, guards (если нужны как провайдеры)
- **Экспорты** - что модуль предоставляет другим модулям
- **JwtModule** - должен быть зарегистрирован в модуле, где используется JwtService
- **PassportModule** - необходим для работы Passport стратегий

### Итоговая структура модуля аутентификации:

```
src/auth/
├── auth.module.ts              # Модуль (объединяет всё)
├── auth.controller.ts          # HTTP эндпоинты
├── auth.service.ts             # Бизнес-логика
├── dto/
│   ├── register.dto.ts         # DTO для регистрации
│   └── login.dto.ts            # DTO для входа
├── guards/
│   └── jwt-auth.guard.ts       # Guard для защиты роутов
├── strategies/
│   └── jwt.strategy.ts         # Стратегия проверки токенов
└── decorators/
    └── current-user.decorator.ts # Декоратор для получения пользователя
```

---

## Следующие шаги:

### Этап 2 (продолжение): Модуль аутентификации
1. ✅ Установить пакеты: bcryptjs, @nestjs/jwt, @nestjs/passport, passport, passport-jwt
2. ✅ Создать DTO для валидации (RegisterDto, LoginDto)
3. ✅ Создать AuthService (регистрация с хешированием пароля, логин с JWT)
4. ✅ Создать JWT Strategy (проверка токенов)
5. ✅ Создать JWT Guard (защита роутов)
6. ✅ Создать AuthController (HTTP эндпоинты)
7. ✅ Создать декоратор @CurrentUser (упрощение доступа к пользователю)
8. ✅ Создать AuthModule (объединение всего)

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

## Полезные команды Prisma:

```bash
# Создать новую миграцию (после изменения schema.prisma)
npm run prisma:migrate -- --name название_миграции
# Пример: npm run prisma:migrate -- --name add_password_to_user

# Применить все миграции к БД
npm run prisma:migrate

# Сгенерировать Prisma Client (после изменения schema.prisma)
npm run prisma:generate

# Открыть Prisma Studio (визуальный редактор БД)
npm run prisma:studio

# Синхронизировать схему с существующей БД (pull)
npm run prisma:db:pull
```

**Важно:**
- После изменения `schema.prisma` всегда нужно:
  1. Создать миграцию: `npm run prisma:migrate -- --name название`
  2. Сгенерировать Client: `npm run prisma:generate`
- Миграции сохраняются в `prisma/migrations/` и коммитятся в Git
- Prisma Studio полезен для просмотра и редактирования данных в БД

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

