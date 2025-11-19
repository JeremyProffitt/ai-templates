# Architecture Standards - AWS Lambda Go/Fiber v1.0

**Organization:** Ally Financial SRE/DevSecOps
**Last Updated:** November 19, 2025

## Overview

This document defines the architecture patterns for AWS Lambda applications using Go and the Fiber framework.

### Technology Stack
- **Runtime**: AWS Lambda with API Gateway
- **Language**: Go 1.21+
- **Framework**: GoFiber v2 with fiber-lambda adapter
- **Database**: Amazon DynamoDB
- **Session Management**: Cookies + DynamoDB
- **Authentication**: Custom implementation with DynamoDB
- **Deployment**: AWS SAM + GitHub Actions
- **Logging**: Verbose structured logging with zerolog
- **Support Model**: 24x7 SRE Team

---

## Serverless Architecture Pattern

```
┌──────────────┐      ┌────────────────┐      ┌──────────────┐
│              │      │                │      │              │
│  API Gateway │─────▶│  Lambda        │─────▶│  DynamoDB    │
│              │      │  (GoFiber)     │      │              │
└──────────────┘      └────────────────┘      └──────────────┘
                             │
                             ▼
                      ┌──────────────┐
                      │  CloudWatch  │
                      │  Logs        │
                      └──────────────┘
```

### Key Principles

1. **Stateless Execution**: Lambda functions are ephemeral
   - No local file storage
   - All state externalized to DynamoDB
   - Session data stored in DynamoDB with TTL

2. **Cold Start Optimization**:
   - Initialize connections in `init()` function
   - Reuse DynamoDB clients across invocations
   - Minimize initialization code in handler

3. **Error Handling**:
   - Never expose internal errors to clients
   - Log all errors with full context
   - Return appropriate HTTP status codes

---

## Project Structure

```
/
├── cmd/
│   └── lambda/
│       └── main.go              # Lambda handler entry point
│
├── internal/
│   ├── api/
│   │   ├── handlers/            # HTTP request handlers
│   │   │   ├── auth.go          # Authentication handlers
│   │   │   ├── user.go          # User handlers
│   │   │   ├── admin.go         # Admin handlers
│   │   │   └── health.go        # Health check
│   │   ├── middleware/          # Custom middleware
│   │   │   ├── auth.go          # Authentication middleware
│   │   │   ├── logging.go       # Request logging
│   │   │   ├── security.go      # Security headers
│   │   │   └── ratelimit.go     # Rate limiting
│   │   └── routes/              # Route definitions
│   │       └── routes.go        # Route setup
│   │
│   ├── auth/
│   │   ├── authenticator.go     # Authentication logic
│   │   ├── permissions.go       # RBAC implementation
│   │   └── session.go           # Session management
│   │
│   ├── config/
│   │   └── config.go            # Configuration management
│   │
│   ├── database/
│   │   ├── dynamodb.go          # DynamoDB client
│   │   ├── models/              # DynamoDB data models
│   │   │   ├── user.go
│   │   │   └── session.go
│   │   └── repository/          # Data access layer
│   │       ├── user_repository.go
│   │       └── session_repository.go
│   │
│   ├── service/
│   │   ├── user_service.go      # User business logic
│   │   └── admin_service.go     # Admin business logic
│   │
│   └── utils/
│       ├── logger.go            # Structured logging
│       ├── errors.go            # Error handling
│       ├── validation.go        # Input validation
│       └── response.go          # Response helpers
│
├── deployments/
│   ├── template.yaml            # SAM template
│   └── samconfig.toml           # SAM configuration
│
├── .github/
│   └── workflows/
│       └── deploy.yml           # GitHub Actions workflow
│
├── tests/
│   ├── integration/             # Integration tests
│   └── unit/                    # Unit tests
│
├── scripts/
│   ├── seed.go                  # Seed test data
│   └── migrate.go               # Database migrations
│
├── Makefile                     # Build commands
├── go.mod
├── go.sum
├── .env.example
└── README.md
```

### Directory Conventions

- **`cmd/`**: Application entry points
- **`internal/`**: Private application code (not importable by other projects)
- **`internal/api/`**: HTTP layer (handlers, middleware, routes)
- **`internal/auth/`**: Authentication and authorization logic
- **`internal/database/`**: Data persistence layer
- **`internal/service/`**: Business logic layer
- **`internal/utils/`**: Shared utilities

---

## Lambda Handler Configuration

### Main Handler (cmd/lambda/main.go)

```go
package main

import (
    "context"
    "log"

    "github.com/aws/aws-lambda-go/events"
    "github.com/aws/aws-lambda-go/lambda"
    fiberadapter "github.com/awslabs/aws-lambda-go-api-proxy/fiber"
    "github.com/gofiber/fiber/v2"

    "yourapp/internal/api/routes"
    "yourapp/internal/config"
    "yourapp/internal/database"
    "yourapp/internal/utils"
)

var fiberLambda *fiberadapter.FiberLambda

// init runs during Lambda cold start - initialize heavy resources here
func init() {
    utils.Logger.Info().
        Str("who", "system:lambda-runtime").
        Str("what", "initializing Lambda function").
        Str("why", "cold start for new container").
        Str("where", "lambda:init").
        Msg("Lambda cold start initiated")

    // Load configuration
    cfg := config.Load()

    // Initialize logger with verbose level
    utils.InitLogger(utils.LogLevelVerbose)

    // Initialize DynamoDB (connection reused across invocations)
    if err := database.InitDynamoDB(cfg); err != nil {
        log.Fatalf("Failed to initialize DynamoDB: %v", err)
    }

    // Setup Fiber app
    app := fiber.New(fiber.Config{
        DisableStartupMessage: true,
        ErrorHandler:          utils.CustomErrorHandler,
        ReadTimeout:           time.Second * 10,
        WriteTimeout:          time.Second * 10,
    })

    // Setup routes
    routes.Setup(app)

    // Create Lambda adapter
    fiberLambda = fiberadapter.New(app)

    utils.Logger.Info().
        Str("who", "system:lambda-runtime").
        Str("what", "completed Lambda initialization").
        Str("why", "cold start completed successfully").
        Str("where", "lambda:init").
        Msg("Lambda function ready")
}

// Handler is the Lambda function handler
func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
    // Log incoming request
    utils.Logger.Debug().
        Str("who", "apigateway:proxy").
        Str("what", "received API Gateway request").
        Str("why", "client request forwarded by API Gateway").
        Str("where", "lambda:handler").
        Str("request_id", req.RequestContext.RequestID).
        Str("path", req.Path).
        Str("method", req.HTTPMethod).
        Msg("Processing API Gateway request")

    return fiberLambda.ProxyWithContext(ctx, req)
}

func main() {
    lambda.Start(Handler)
}
```

### Cold Start Optimization

**DO:**
- ✅ Initialize DynamoDB client in `init()`
- ✅ Initialize logger in `init()`
- ✅ Load configuration in `init()`
- ✅ Setup Fiber app in `init()`
- ✅ Reuse connections across invocations

**DON'T:**
- ❌ Create new DynamoDB client on each request
- ❌ Initialize heavy resources in handler
- ❌ Use local file storage
- ❌ Keep state in memory between invocations

---

## Configuration Management

### Configuration Structure

```go
// internal/config/config.go
package config

import (
    "os"
    "time"
)

type Config struct {
    // Service Info
    ServiceName string
    Environment string
    Version     string
    AWSRegion   string

    // DynamoDB Tables
    UsersTable       string
    SessionsTable    string
    PermissionsTable string

    // Session Configuration
    SessionDuration time.Duration
    CookieSecure    bool
    CookieHTTPOnly  bool
    CookieSameSite  string

    // Security
    JWTSecret      string
    EncryptionKey  string

    // Rate Limiting
    MaxLoginAttempts int
    RateLimitWindow  time.Duration

    // Logging
    LogLevel string
}

func Load() *Config {
    return &Config{
        ServiceName: getEnv("SERVICE_NAME", "gofiber-app"),
        Environment: getEnv("ENVIRONMENT", "dev"),
        Version:     getEnv("VERSION", "1.0.0"),
        AWSRegion:   getEnv("AWS_REGION", "us-east-1"),

        UsersTable:       getEnv("USERS_TABLE", "dev-users"),
        SessionsTable:    getEnv("SESSIONS_TABLE", "dev-sessions"),
        PermissionsTable: getEnv("PERMISSIONS_TABLE", "dev-permissions"),

        SessionDuration: parseDuration(getEnv("SESSION_DURATION", "24h")),
        CookieSecure:    getEnvBool("COOKIE_SECURE", true),
        CookieHTTPOnly:  getEnvBool("COOKIE_HTTPONLY", true),
        CookieSameSite:  getEnv("COOKIE_SAMESITE", "Strict"),

        JWTSecret:     getEnv("JWT_SECRET", ""),
        EncryptionKey: getEnv("ENCRYPTION_KEY", ""),

        MaxLoginAttempts: getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
        RateLimitWindow:  parseDuration(getEnv("RATE_LIMIT_WINDOW", "15m")),

        LogLevel: getEnv("LOG_LEVEL", "VERBOSE"),
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
    value := os.Getenv(key)
    if value == "true" || value == "1" {
        return true
    }
    if value == "false" || value == "0" {
        return false
    }
    return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
    value := os.Getenv(key)
    if i, err := strconv.Atoi(value); err == nil {
        return i
    }
    return defaultValue
}

func parseDuration(s string) time.Duration {
    d, err := time.ParseDuration(s)
    if err != nil {
        return 24 * time.Hour // default
    }
    return d
}
```

---

## Lambda Best Practices

### 1. Memory and Timeout Configuration

```yaml
# SAM template
Resources:
  ApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      Timeout: 30              # Maximum 30 seconds
      MemorySize: 512          # 512MB minimum recommended
      Architectures:
        - arm64                # Use ARM64 for cost savings
```

**Recommendations:**
- **Dev**: 512MB memory, 60s timeout
- **Staging**: 1024MB memory, 30s timeout
- **Production**: 1024MB+ memory, 30s timeout

### 2. Error Handling

```go
// Always handle errors gracefully
func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
    defer func() {
        if r := recover(); r != nil {
            utils.Logger.Error().
                Str("who", "system:lambda-runtime").
                Str("what", "recovered from panic").
                Str("why", "unhandled panic in handler").
                Str("where", "lambda:handler").
                Interface("panic", r).
                Msg("Lambda panic recovered")
        }
    }()

    return fiberLambda.ProxyWithContext(ctx, req)
}
```

### 3. Context Propagation

```go
// Always pass context through the call chain
func (s *UserService) GetUser(ctx context.Context, userID string) (*models.User, error) {
    // Context carries deadlines, cancellation signals
    user, err := s.repo.FindByID(ctx, userID)
    if err != nil {
        return nil, err
    }
    return user, nil
}
```

### 4. Graceful Degradation

```go
// Fail gracefully when external services are unavailable
func (s *EmailService) SendEmail(ctx context.Context, to, subject, body string) error {
    if err := s.smtp.Send(ctx, to, subject, body); err != nil {
        // Log error but don't fail the request
        utils.Logger.Warn().
            Str("who", "system:email-service").
            Str("what", "failed to send email").
            Str("why", "SMTP server unavailable").
            Str("where", "external:smtp-server").
            Err(err).
            Msg("Email delivery failed - continuing")

        // Queue for retry or notify admins
        return nil // Don't fail the user's request
    }
    return nil
}
```

---

## Related Documentation

- **Coding Standards**: [standards/CODING_STANDARDS.md](./CODING_STANDARDS.md)
- **Security Standards**: [standards/SECURITY_STANDARDS.md](./SECURITY_STANDARDS.md)
- **Database Standards**: [standards/DATABASE_STANDARDS.md](./DATABASE_STANDARDS.md)
- **Logging Standards**: [standards/LOGGING_STANDARDS.md](./LOGGING_STANDARDS.md)
- **Deployment Standards**: [standards/DEPLOYMENT_STANDARDS.md](./DEPLOYMENT_STANDARDS.md)

---

**Version:** 1.0
**Maintainer:** DevOps/SRE Team
**Review Schedule:** Quarterly
