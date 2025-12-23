# Dummy Event - Auth Service

A production-ready **Modular Monolith Clean Architecture** backend built with Go (Golang), designed for easy migration to microservices.

## 🏗️ Architecture

This project follows **Clean Architecture** principles with a modular monolith approach:

```
├── cmd/                    # Application entry points
│   └── api/               # HTTP API server
├── internal/              # Private application code
│   ├── config/           # Configuration management
│   ├── infrastructure/   # External services (DB, Cache, Server)
│   └── modules/          # Feature modules
│       └── auth/         # Authentication module
│           ├── domain/       # Business logic & entities
│           ├── application/  # Use cases & DTOs
│           ├── infrastructure/ # Implementations
│           └── interfaces/   # HTTP handlers
├── pkg/                  # Public shared packages
├── migrations/           # Database migrations
├── scripts/              # Utility scripts
└── docker/               # Docker configuration
```

## ✨ Features

### Auth Module
- **Google OAuth2 Login** - Login with Google account
- **Email OTP Login** - Fallback login with email verification
- **JWT with RSA** - Secure token generation using RS256
- **Token Refresh** - Automatic token rotation
- **Logout** - Token revocation with blacklist
- **Profile Management** - View and update user profile

### Security Features
- RSA-256 JWT signing
- AES-256-GCM encryption for sensitive data
- OAuth state validation (CSRF protection)
- Token blacklisting
- Rate limiting for OTP
- Password-less authentication

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- Docker & Docker Compose
- OpenSSL (for key generation)

### 1. Clone and Setup

```bash
cd /path/to/dummy-event

# Generate RSA keys for JWT
chmod +x scripts/generate_rsa_keys.sh
./scripts/generate_rsa_keys.sh

# Copy the generated ENCRYPTION_KEY to .env file
```

### 2. Configure Environment

```bash
# Copy example env file
cp .env.example .env

# Edit .env with your configuration
# - Add Google OAuth credentials
# - Add SMTP settings (for email OTP)
# - Add ENCRYPTION_KEY from key generation step
```

### 3. Start with Docker

```bash
# Start PostgreSQL and Redis
cd docker
docker-compose up -d postgres redis

# Run migrations (automatically done on container start)
# Or manually:
docker exec -i dummy-event-postgres psql -U postgres -d dummy_event < ../migrations/001_create_users_table.sql

# Go back to root and run the app
cd ..
go mod download
go run cmd/api/main.go
```

### 4. Or Start Everything with Docker

```bash
cd docker
docker-compose up -d
```

## 📚 API Endpoints

### Public Endpoints (No authentication required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/auth/google` | Redirect to Google OAuth |
| GET | `/api/v1/auth/google/url` | Get Google OAuth URL (JSON) |
| GET | `/api/v1/auth/google/callback` | Google OAuth callback |
| POST | `/api/v1/auth/email/send-otp` | Send OTP to email |
| POST | `/api/v1/auth/email/verify-otp` | Verify OTP and login |
| POST | `/api/v1/auth/refresh` | Refresh access token |

### Protected Endpoints (Authentication required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/logout` | Logout (revoke token) |
| GET | `/api/v1/auth/profile` | Get user profile |
| PUT | `/api/v1/auth/profile` | Update user profile |

## 📖 API Examples

### Google OAuth Flow

```bash
# 1. Get OAuth URL (for SPA apps)
curl http://localhost:3000/api/v1/auth/google/url

# 2. Or redirect directly to Google
# Open in browser: http://localhost:3000/api/v1/auth/google
```

### Email OTP Flow

```bash
# 1. Send OTP
curl -X POST http://localhost:3000/api/v1/auth/email/send-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# 2. Verify OTP
curl -X POST http://localhost:3000/api/v1/auth/email/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "otp": "123456"}'
```

### Token Refresh

```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "your-refresh-token"}'
```

### Get Profile

```bash
curl http://localhost:3000/api/v1/auth/profile \
  -H "Authorization: Bearer your-access-token"
```

### Logout

```bash
curl -X POST http://localhost:3000/api/v1/auth/logout \
  -H "Authorization: Bearer your-access-token"
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_PORT` | HTTP server port | `3000` |
| `APP_ENV` | Environment (development/production) | `development` |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | PostgreSQL user | `postgres` |
| `DB_PASSWORD` | PostgreSQL password | `postgres` |
| `DB_NAME` | PostgreSQL database | `dummy_event` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | (required) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | (required) |
| `JWT_PRIVATE_KEY_PATH` | Path to RSA private key | `./keys/private.pem` |
| `JWT_PUBLIC_KEY_PATH` | Path to RSA public key | `./keys/public.pem` |
| `ENCRYPTION_KEY` | AES-256 encryption key (base64) | (required) |

## 🗄️ Redis Key Schema

| Key Pattern | Value | TTL | Description |
|------------|-------|-----|-------------|
| `google:access_token:{user_id}` | Google access token | ~1 hour | Short-lived Google token |
| `app:refresh_token:{jti}` | User ID | 7 days | Refresh token lookup |
| `otp:{hashed_email}` | 6-digit OTP | 5 minutes | Email verification |
| `otp:attempts:{hashed_email}` | Attempt count | 5 minutes | Rate limiting |
| `blacklist:{jti}` | "revoked" | Token expiry | Revoked tokens |
| `oauth:state:{state}` | "valid" | 10 minutes | CSRF protection |

## 🔐 Security Considerations

1. **Private keys** - Never commit to version control
2. **Refresh tokens** - Stored encrypted in PostgreSQL (not Redis)
3. **Google tokens** - Never exposed to client
4. **OTP rate limiting** - Max 3 attempts per OTP
5. **Token rotation** - Refresh tokens are rotated on use
6. **Blacklisting** - Tokens can be revoked immediately

## 🧪 Testing

```bash
# Run tests
go test ./... -v

# Run with coverage
go test ./... -v -cover

# Run specific module tests
go test ./internal/modules/auth/... -v
```

## 📦 Building

```bash
# Build binary
go build -o bin/api ./cmd/api

# Build Docker image
docker build -f docker/Dockerfile -t dummy-event:latest .
```

## 🔄 Future Microservices Migration

This modular monolith is designed for easy migration to microservices:

1. Each module (`auth`, `product`, `order`, etc.) is self-contained
2. Modules communicate through interfaces, not direct dependencies
3. Shared packages (`pkg/`) are minimal and stateless
4. Database schema is module-scoped
5. Configuration is centralized but module-specific

To migrate:
1. Extract module to separate repository
2. Replace in-memory interfaces with HTTP/gRPC clients
3. Add service discovery
4. Deploy independently

## 📝 License

MIT License

## 👨‍💻 Author

Built with ❤️ using Go
