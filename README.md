# Spring JWT Auth Starter

![Java](https://img.shields.io/badge/Java-17-ED8B00?style=flat-square)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-4.1-6DB33F?style=flat-square)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17-4169E1?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-7F5AF0?style=flat-square)

A production-ready authentication backend you can clone and build on. It handles registration, login, short-lived access tokens, rotating refresh tokens and role-based access, so a new project can start from the features instead of the login screen.

## Features

- **Register and log in** with email and password (BCrypt hashed)
- **Stateless JWT access tokens** (HS256, 15 minutes by default)
- **Rotating refresh tokens**: single use, stored as SHA-256 hashes, revocable on logout
- **Reuse detection**: presenting an already-used refresh token revokes all of that user's sessions
- **Role-based access** (`USER`, `ADMIN`) with URL rules and `@PreAuthorize`
- **Validation and clean errors** returned as RFC 9457 `application/problem+json`
- **Swagger UI** with an *Authorize* button for testing protected endpoints
- **Runs anywhere**: H2 in memory with zero setup, or PostgreSQL through Docker Compose
- **Integration tests** for the whole flow, run in CI on every push

## How it works

```
 Client                              API
   |  POST /api/auth/login            |
   |--------------------------------->|  check password (BCrypt)
   |  { accessToken, refreshToken }   |  sign JWT, store hash of refresh token
   |<---------------------------------|
   |                                  |
   |  GET /api/users/me               |
   |  Authorization: Bearer <access>  |
   |--------------------------------->|  JwtAuthenticationFilter verifies signature + expiry
   |  200 { user }                    |
   |<---------------------------------|
   |                                  |
   |  (access token expired)          |
   |  POST /api/auth/refresh          |
   |--------------------------------->|  revoke old refresh token, issue a new pair
   |  { accessToken, refreshToken }   |
   |<---------------------------------|
```

## Quick start

**Option 1: no database needed (H2 in memory)**

```bash
./mvnw spring-boot:run
```

**Option 2: with PostgreSQL**

```bash
docker compose up --build
```

Then open **http://localhost:8080/swagger-ui.html**.

A default admin account is created on first start: `admin@example.com` / `Admin123!`. Change it with the `ADMIN_EMAIL` and `ADMIN_PASSWORD` environment variables.

## API

| Method | Endpoint | Access | Description |
|---|---|---|---|
| POST | `/api/auth/register` | Public | Create an account, returns a token pair |
| POST | `/api/auth/login` | Public | Log in, returns a token pair |
| POST | `/api/auth/refresh` | Public | Exchange a refresh token for a new pair |
| POST | `/api/auth/logout` | Public | Revoke a refresh token |
| GET | `/api/users/me` | Authenticated | Current user's profile |
| GET | `/api/admin/users` | Admin | List all users |
| PATCH | `/api/admin/users/{id}/role` | Admin | Change a user's role |

**Example**

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","password":"Password1","fullName":"Jane Doe"}'
```

```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "refreshToken": "q3Vx0f...",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "user": { "id": 2, "email": "jane@example.com", "fullName": "Jane Doe", "role": "USER" }
}
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | dev-only value | Base64 HMAC key, at least 256 bits. Generate with `openssl rand -base64 64` |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin@example.com` / `Admin123!` | Seeded admin account |
| `SPRING_PROFILES_ACTIVE` | *(none)* | Set to `postgres` to use PostgreSQL |
| `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | local Postgres | Database connection for the `postgres` profile |

Token lifetimes are set in `application.properties` (`app.jwt.access-token-ttl`, `app.jwt.refresh-token-ttl`).

## Project structure

```
src/main/java/dev/bayram/auth
├── auth/       AuthController, AuthService, refresh tokens, DTOs
├── security/   SecurityConfig, JwtService, JwtAuthenticationFilter, Swagger setup
├── user/       User entity, repository, profile and admin endpoints
└── common/     Error handling and admin seeding
```

## Running the tests

```bash
./mvnw test
```

## Using it in your own project

1. Click **Use this template** on GitHub, or clone the repo.
2. Rename the package `dev.bayram.auth` to your own.
3. Add your entities and controllers. Any endpoint outside `/api/auth/**` is protected by default.

## License

MIT
