# PROJECT_STANDARDS.md - AWS Lambda Go/Fiber Reference v1.0

## Context and Constraints
- **Organization**: Ally Financial SRE/DevSecOps
- **Runtime**: AWS Lambda with API Gateway
- **Language**: Go 1.21+
- **Framework**: GoFiber v2 with fiber-lambda adapter
- **Session Management**: Cookies + DynamoDB
- **Authentication**: Custom implementation with DynamoDB
- **Deployment**: AWS SAM + GitHub Actions
- **Logging Level**: VERBOSE (Debug-level in production)
- **Support Model**: 24x7 SRE Team

## Quick Reference for Claude Code
```
This is a serverless Go application using Fiber framework on AWS Lambda.
All code must be optimized for Lambda cold starts and stateless execution.
Session state is externalized to DynamoDB. No local file storage.
```

---

## Architecture Standards

### Serverless Architecture Pattern
```
AWS API Gateway → Lambda Function → GoFiber Application → DynamoDB
                                   ↓
                            CloudWatch Logs
```

### Project Structure
```
/
├── cmd/
│   └── lambda/
│       └── main.go              # Lambda handler entry point
├── internal/
│   ├── api/
│   │   ├── handlers/            # HTTP request handlers
│   │   ├── middleware/          # Custom middleware
│   │   └── routes/              # Route definitions
│   ├── auth/
│   │   ├── authenticator.go     # Authentication logic
│   │   ├── permissions.go       # RBAC implementation
│   │   └── session.go           # Session management
│   ├── config/
│   │   └── config.go            # Configuration management
│   ├── database/
│   │   ├── dynamodb.go          # DynamoDB client
│   │   └── models/              # DynamoDB data models
│   ├── service/
│   │   └── [domain]/            # Business logic by domain
│   └── utils/
│       ├── logger.go            # Structured logging
│       └── errors.go            # Error handling
├── deployments/
│   ├── template.yaml            # SAM template
│   └── samconfig.toml           # SAM configuration
├── .github/
│   └── workflows/
│       └── deploy.yml           # GitHub Actions workflow
├── Makefile                     # Build commands
├── go.mod
└── go.sum
```

### Lambda Handler Configuration
```go
// cmd/lambda/main.go
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

func init() {
    // Initialize during cold start
    cfg := config.Load()
    
    // Initialize logger with verbose level
    utils.InitLogger(utils.LogLevelVerbose)
    
    // Initialize DynamoDB
    database.InitDynamoDB(cfg)
    
    // Setup Fiber app
    app := fiber.New(fiber.Config{
        DisableStartupMessage: true,
        ErrorHandler: utils.CustomErrorHandler,
    })
    
    // Setup routes
    routes.Setup(app)
    
    // Create Lambda adapter
    fiberLambda = fiberadapter.New(app)
}

func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
    // Log request details (verbose)
    utils.Logger.Debug().
        Str("request_id", req.RequestContext.RequestID).
        Str("path", req.Path).
        Str("method", req.HTTPMethod).
        Interface("headers", req.Headers).
        Msg("Incoming Lambda request")
    
    return fiberLambda.ProxyWithContext(ctx, req)
}

func main() {
    lambda.Start(Handler)
}
```

---

## Coding Standards

### Go/Fiber Specific Patterns

#### Route Organization
```go
// internal/api/routes/routes.go
package routes

import (
    "github.com/gofiber/fiber/v2"
    "yourapp/internal/api/handlers"
    "yourapp/internal/api/middleware"
)

func Setup(app *fiber.App) {
    // Global middleware
    app.Use(middleware.RequestLogger())
    app.Use(middleware.SessionManager())
    app.Use(middleware.SecurityHeaders())
    
    // Health check (no auth required)
    app.Get("/health", handlers.HealthCheck)
    
    // Public routes
    public := app.Group("/api/v1")
    public.Post("/login", handlers.Login)
    public.Post("/register", handlers.Register)
    public.Post("/logout", handlers.Logout)
    
    // Protected routes
    protected := app.Group("/api/v1", middleware.RequireAuth())
    protected.Get("/profile", handlers.GetProfile)
    protected.Put("/profile", handlers.UpdateProfile)
    
    // Admin routes
    admin := app.Group("/api/v1/admin", 
        middleware.RequireAuth(),
        middleware.RequirePermission("admin"))
    admin.Get("/users", handlers.ListUsers)
    admin.Delete("/users/:id", handlers.DeleteUser)
}
```

#### Error Handling Pattern
```go
// internal/utils/errors.go
package utils

import (
    "github.com/gofiber/fiber/v2"
)

type AppError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details any    `json:"details,omitempty"`
}

func CustomErrorHandler(c *fiber.Ctx, err error) error {
    // Log all errors verbosely
    Logger.Error().
        Err(err).
        Str("path", c.Path()).
        Str("method", c.Method()).
        Str("ip", c.IP()).
        Interface("headers", c.GetReqHeaders()).
        Msg("Request error")
    
    code := fiber.StatusInternalServerError
    
    if e, ok := err.(*fiber.Error); ok {
        code = e.Code
    }
    
    return c.Status(code).JSON(AppError{
        Code:    "ERROR",
        Message: err.Error(),
    })
}
```

---

## Session Management Standards

### Cookie Configuration
```go
// internal/auth/session.go
package auth

import (
    "time"
    "github.com/gofiber/fiber/v2"
)

const (
    SessionCookieName = "session_id"
    SessionDuration   = 24 * time.Hour
)

type SessionConfig struct {
    CookieName string
    Secure     bool
    HTTPOnly   bool
    SameSite   string
    MaxAge     int
}

func GetSessionConfig() SessionConfig {
    return SessionConfig{
        CookieName: SessionCookieName,
        Secure:     true,  // Always true for production
        HTTPOnly:   true,  // Prevent JS access
        SameSite:   "Strict",
        MaxAge:     int(SessionDuration.Seconds()),
    }
}

func SetSessionCookie(c *fiber.Ctx, sessionID string) {
    config := GetSessionConfig()
    c.Cookie(&fiber.Cookie{
        Name:     config.CookieName,
        Value:    sessionID,
        Expires:  time.Now().Add(SessionDuration),
        Secure:   config.Secure,
        HTTPOnly: config.HTTPOnly,
        SameSite: config.SameSite,
    })
}
```

### DynamoDB Session Storage
```go
// internal/database/models/session.go
package models

import (
    "time"
)

type Session struct {
    SessionID  string    `dynamodbav:"session_id"`  // Partition Key
    UserID     string    `dynamodbav:"user_id"`
    Email      string    `dynamodbav:"email"`
    CreatedAt  time.Time `dynamodbav:"created_at"`
    ExpiresAt  time.Time `dynamodbav:"expires_at"`
    IPAddress  string    `dynamodbav:"ip_address"`
    UserAgent  string    `dynamodbav:"user_agent"`
    IsActive   bool      `dynamodbav:"is_active"`
}

// DynamoDB Table Configuration
/*
Table Name: app-sessions
Partition Key: session_id (String)
TTL Attribute: expires_at
Global Secondary Index: 
  - Name: UserIDIndex
  - Partition Key: user_id
  - Projection: ALL
*/
```

---

## Authentication & Authorization Standards

### User Model with Permissions
```go
// internal/database/models/user.go
package models

import (
    "time"
    "golang.org/x/crypto/bcrypt"
)

type User struct {
    UserID      string            `dynamodbav:"user_id"`      // Partition Key
    Email       string            `dynamodbav:"email"`        // GSI
    Username    string            `dynamodbav:"username"`     // GSI
    Password    string            `dynamodbav:"password"`     // Hashed
    Permissions []string          `dynamodbav:"permissions"`
    Roles       []string          `dynamodbav:"roles"`
    Metadata    map[string]string `dynamodbav:"metadata"`
    CreatedAt   time.Time        `dynamodbav:"created_at"`
    UpdatedAt   time.Time        `dynamodbav:"updated_at"`
    LastLogin   *time.Time       `dynamodbav:"last_login,omitempty"`
    IsActive    bool             `dynamodbav:"is_active"`
    MFAEnabled  bool             `dynamodbav:"mfa_enabled"`
    MFASecret   string           `dynamodbav:"mfa_secret,omitempty"`
}

// DynamoDB Table Configuration
/*
Table Name: app-users
Partition Key: user_id (String)
Global Secondary Indexes:
  - Name: EmailIndex
    Partition Key: email
  - Name: UsernameIndex  
    Partition Key: username
*/

func (u *User) HashPassword(password string) error {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    if err != nil {
        return err
    }
    u.Password = string(bytes)
    return nil
}

func (u *User) CheckPassword(password string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
    return err == nil
}
```

### Permission System
```go
// internal/auth/permissions.go
package auth

type Permission string

const (
    PermissionRead   Permission = "read"
    PermissionWrite  Permission = "write"
    PermissionDelete Permission = "delete"
    PermissionAdmin  Permission = "admin"
)

type Role struct {
    Name        string       `dynamodbav:"name"`
    Permissions []Permission `dynamodbav:"permissions"`
}

var DefaultRoles = map[string][]Permission{
    "user": {
        PermissionRead,
    },
    "editor": {
        PermissionRead,
        PermissionWrite,
    },
    "admin": {
        PermissionRead,
        PermissionWrite,
        PermissionDelete,
        PermissionAdmin,
    },
}

func HasPermission(userPermissions []string, required Permission) bool {
    for _, p := range userPermissions {
        if p == string(required) || p == string(PermissionAdmin) {
            return true
        }
    }
    return false
}
```

### Authentication Middleware
```go
// internal/api/middleware/auth.go
package middleware

import (
    "github.com/gofiber/fiber/v2"
    "yourapp/internal/auth"
    "yourapp/internal/database"
    "yourapp/internal/utils"
)

func RequireAuth() fiber.Handler {
    return func(c *fiber.Ctx) error {
        sessionID := c.Cookies(auth.SessionCookieName)
        
        if sessionID == "" {
            utils.Logger.Debug().Msg("No session cookie found")
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Unauthorized",
            })
        }
        
        // Verify session in DynamoDB
        session, err := database.GetSession(sessionID)
        if err != nil || !session.IsActive {
            utils.Logger.Debug().
                Str("session_id", sessionID).
                Msg("Invalid or expired session")
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Invalid session",
            })
        }
        
        // Get user from DynamoDB
        user, err := database.GetUser(session.UserID)
        if err != nil {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "User not found",
            })
        }
        
        // Store in context
        c.Locals("user", user)
        c.Locals("session", session)
        
        return c.Next()
    }
}

func RequirePermission(permission string) fiber.Handler {
    return func(c *fiber.Ctx) error {
        user := c.Locals("user").(*models.User)
        
        if !auth.HasPermission(user.Permissions, auth.Permission(permission)) {
            utils.Logger.Warn().
                Str("user_id", user.UserID).
                Str("required_permission", permission).
                Strs("user_permissions", user.Permissions).
                Msg("Permission denied")
            
            return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
                "error": "Insufficient permissions",
            })
        }
        
        return c.Next()
    }
}
```

---

## Logging Standards

> **⚠️ IMPORTANT**: See [LOGGING_STANDARDS.md](./LOGGING_STANDARDS.md) for complete observability specification.
>
> All logs MUST include the four human-readable context fields:
> - **who**: Actor/subject (e.g., "user:john@example.com", "system:scheduler")
> - **what**: Action performed (e.g., "created user account", "validated session")
> - **why**: Purpose/reason in ONE sentence (e.g., "user registration completed")
> - **where**: System/component (e.g., "auth-service:login-handler")

### Structured Logging Configuration
```go
// internal/utils/logger.go
package utils

import (
    "os"
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
)

type LogLevel string

const (
    LogLevelVerbose LogLevel = "VERBOSE"
    LogLevelDebug   LogLevel = "DEBUG"
    LogLevelInfo    LogLevel = "INFO"
    LogLevelWarn    LogLevel = "WARN"
    LogLevelError   LogLevel = "ERROR"
)

var Logger zerolog.Logger

func InitLogger(level LogLevel) {
    // Set verbose logging for Lambda/CloudWatch
    zerolog.SetGlobalLevel(zerolog.DebugLevel)

    // Configure for CloudWatch JSON format
    Logger = zerolog.New(os.Stdout).With().
        Timestamp().
        Str("service", os.Getenv("SERVICE_NAME")).
        Str("environment", os.Getenv("ENVIRONMENT")).
        Str("version", os.Getenv("VERSION")).
        Logger()

    Logger.Info().
        Str("who", "system:logger").
        Str("what", "initialized logging system").
        Str("why", "application startup").
        Str("where", "utils:logger").
        Str("log_level", string(level)).
        Msg("Logger initialized successfully")
}

// Request logging middleware with human-readable context
func RequestLogger() fiber.Handler {
    return func(c *fiber.Ctx) error {
        start := time.Now()

        // Determine who is making the request
        who := "anonymous"
        if user := c.Locals("user"); user != nil {
            if u, ok := user.(*models.User); ok {
                who = fmt.Sprintf("user:%s", u.Email)
            }
        }

        // Log request with human-readable context
        Logger.Info().
            Str("who", who).
            Str("what", fmt.Sprintf("received %s request", c.Method())).
            Str("why", "client API call initiated").
            Str("where", fmt.Sprintf("api:%s", c.Path())).
            Str("request_id", c.Get("X-Request-ID")).
            Str("method", c.Method()).
            Str("path", c.Path()).
            Str("ip", c.IP()).
            Msg("API request received")

        // Process request
        err := c.Next()

        // Log response with context
        duration := time.Since(start)
        statusCode := c.Response().StatusCode()

        Logger.Info().
            Str("who", who).
            Str("what", fmt.Sprintf("completed %s request", c.Method())).
            Str("why", fmt.Sprintf("returned HTTP %d", statusCode)).
            Str("where", fmt.Sprintf("api:%s", c.Path())).
            Str("request_id", c.Get("X-Request-ID")).
            Int("status", statusCode).
            Dur("duration_ms", duration).
            Msg("API request completed")

        return err
    }
}
```

### Mandatory Logging Pattern - ALWAYS USE THIS FORMAT
```go
// Every log MUST include: who, what, why, where

// ✅ CORRECT - User action
Logger.Info().
    Str("who", "user:john@example.com").
    Str("what", "updated user profile").
    Str("why", "user submitted profile changes via API").
    Str("where", "user-service:profile-handler").
    Str("user_id", userID).
    Msg("Profile updated successfully")

// ✅ CORRECT - System action
Logger.Debug().
    Str("who", "system:user-repository").
    Str("what", "queried users table").
    Str("why", "authentication check in progress").
    Str("where", "database:dynamodb-users").
    Str("table", tableName).
    Dur("duration_ms", duration).
    Msg("DynamoDB query completed")

// ✅ CORRECT - External service
Logger.Info().
    Str("who", "system:email-service").
    Str("what", "sent password reset email").
    Str("why", "user requested password reset").
    Str("where", "external:smtp-server").
    Str("recipient", user.Email).
    Msg("Password reset email sent")

// ✅ CORRECT - Scheduled job
Logger.Info().
    Str("who", "system:scheduler").
    Str("what", "completed cleanup job").
    Str("why", "daily maintenance task finished").
    Str("where", "job:session-cleanup").
    Int("deleted_count", deleted).
    Msg("Cleanup job completed")

// ✅ CORRECT - Security event
Logger.Warn().
    Str("who", "user:suspicious@example.com").
    Str("what", "failed login attempt").
    Str("why", "incorrect password provided (attempt 3/5)").
    Str("where", "auth-service:login-handler").
    Str("ip", clientIP).
    Msg("Failed login - approaching lockout threshold")

// ❌ WRONG - Missing context fields
Logger.Info().
    Str("user_id", userID).
    Str("action", "login_attempt").
    Msg("User authentication attempt")

// ❌ WRONG - Not human-readable
Logger.Debug().
    Str("op", "GET_ITEM").
    Str("tbl", "usr").
    Msg("DB_OP_COMPLETE")

// ❌ WRONG - 'why' too long (should be max 100 chars, one sentence)
Logger.Info().
    Str("who", "user:john@example.com").
    Str("what", "created account").
    Str("why", "The user filled out the registration form with their email address and password and then clicked the submit button which triggered the backend validation logic and after passing all validation checks the account was successfully created in the database.").
    Str("where", "auth-service").
    Msg("Account created")

// ❌ WRONG - 'why' is too technical, should explain business reason
Logger.Info().
    Str("who", "system:api").
    Str("what", "executed function").
    Str("why", "handler.CreateUser() was invoked with context").
    Str("where", "api").
    Msg("Function executed")
```

### Field Guidelines

#### 'who' Field - Actor/Subject
- Format: `{type}:{identifier}`
- Examples:
  - `user:john@example.com` - Authenticated user by email
  - `user:user_123456` - User by ID (when email not available)
  - `system:scheduler` - System scheduled job
  - `system:user-service` - System service/component
  - `apikey:prod_key_789` - API key authentication
  - `service:payment-api` - External service
  - `admin:support_team` - Admin user
  - `anonymous` - Unauthenticated request
- **Max Length**: 50 characters

#### 'what' Field - Action Performed
- Format: `{verb} {object}` in past tense
- Examples:
  - `created user account`
  - `updated user profile`
  - `deleted API key`
  - `validated session token`
  - `sent password reset email`
  - `queried users table`
  - `failed login attempt`
  - `completed cleanup job`
- **Max Length**: 60 characters

#### 'why' Field - Business/Technical Reason (MOST IMPORTANT)
- Format: Single sentence explaining the purpose
- Focus: Business reason, not technical implementation
- Examples:
  - ✅ `user registration completed successfully`
  - ✅ `session expired after 24 hours`
  - ✅ `admin requested user data export`
  - ✅ `detected 5 failed login attempts`
  - ✅ `scheduled daily backup job`
  - ❌ `function returned without error` (too technical)
  - ❌ `validation passed and database write succeeded` (too technical)
- **Max Length**: 100 characters, ONE sentence only
- **Must be**: Human-readable business justification

#### 'where' Field - System/Component Location
- Format: `{service}:{component}` or readable name
- Examples:
  - `auth-service:login-handler`
  - `user-service:profile-updater`
  - `database:dynamodb-users`
  - `middleware:session-validator`
  - `external:payment-gateway`
  - `job:session-cleanup`
  - `api:webhook-receiver`
- **Max Length**: 50 characters

### Lambda Cold Start Logging
```go
// Log Lambda cold starts with context
Logger.Info().
    Str("who", "system:lambda-runtime").
    Str("what", "initialized Lambda function").
    Str("why", "cold start for new container").
    Str("where", "lambda:init").
    Dur("init_duration_ms", initDuration).
    Msg("Lambda function cold start")
```

### Error Logging Pattern
```go
// Always include Err(err) field for errors
Logger.Error().
    Str("who", "system:payment-service").
    Str("what", "failed to process payment").
    Str("why", "external payment gateway timeout").
    Str("where", "payment-service:charge-handler").
    Err(err).
    Interface("details", map[string]interface{}{
        "transaction_id": txnID,
        "amount": amount,
        "gateway": "stripe",
    }).
    Msg("Payment processing failed")
```

---

## DynamoDB Standards

### Table Design
```yaml
Users Table:
  TableName: ${STAGE}-users
  PartitionKey: user_id (String)
  GlobalSecondaryIndexes:
    - EmailIndex:
        PartitionKey: email
    - UsernameIndex:
        PartitionKey: username
  
Sessions Table:
  TableName: ${STAGE}-sessions
  PartitionKey: session_id (String)
  TTL: expires_at
  GlobalSecondaryIndexes:
    - UserIDIndex:
        PartitionKey: user_id
        
Permissions Table:
  TableName: ${STAGE}-permissions
  PartitionKey: role_name (String)
  SortKey: permission (String)
```

### DynamoDB Client Configuration
```go
// internal/database/dynamodb.go
package database

import (
    "context"
    "time"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/dynamodb"
    "github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
)

var (
    client *dynamodb.Client
    tables map[string]string
)

func InitDynamoDB(cfg *AppConfig) error {
    awsCfg, err := config.LoadDefaultConfig(context.TODO(),
        config.WithRegion(cfg.AWSRegion),
    )
    if err != nil {
        return err
    }
    
    client = dynamodb.NewFromConfig(awsCfg)
    
    tables = map[string]string{
        "users":       cfg.Environment + "-users",
        "sessions":    cfg.Environment + "-sessions",
        "permissions": cfg.Environment + "-permissions",
    }
    
    return nil
}

// Session operations
func CreateSession(session *models.Session) error {
    av, err := attributevalue.MarshalMap(session)
    if err != nil {
        Logger.Error().Err(err).Msg("Failed to marshal session")
        return err
    }
    
    _, err = client.PutItem(context.TODO(), &dynamodb.PutItemInput{
        TableName: aws.String(tables["sessions"]),
        Item:      av,
    })
    
    Logger.Debug().
        Str("session_id", session.SessionID).
        Str("user_id", session.UserID).
        Msg("Session created in DynamoDB")
    
    return err
}
```

---

## Deployment Standards

### SAM Template
```yaml
# deployments/template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: GoFiber Lambda Application

Globals:
  Function:
    Timeout: 30
    MemorySize: 512
    Runtime: provided.al2
    Architectures:
      - arm64
    Environment:
      Variables:
        SERVICE_NAME: !Ref ServiceName
        ENVIRONMENT: !Ref Environment
        LOG_LEVEL: VERBOSE

Parameters:
  ServiceName:
    Type: String
    Default: gofiber-app
  Environment:
    Type: String
    Default: dev
    AllowedValues:
      - dev
      - staging
      - prod

Resources:
  ApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub ${ServiceName}-${Environment}
      CodeUri: ../
      Handler: bootstrap
      Events:
        ApiEvent:
          Type: Api
          Properties:
            Path: /{proxy+}
            Method: ANY
      Environment:
        Variables:
          USERS_TABLE: !Ref UsersTable
          SESSIONS_TABLE: !Ref SessionsTable
          PERMISSIONS_TABLE: !Ref PermissionsTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
        - DynamoDBCrudPolicy:
            TableName: !Ref SessionsTable
        - DynamoDBCrudPolicy:
            TableName: !Ref PermissionsTable
    Metadata:
      BuildMethod: makefile

  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub ${Environment}-users
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: user_id
          AttributeType: S
        - AttributeName: email
          AttributeType: S
        - AttributeName: username
          AttributeType: S
      KeySchema:
        - AttributeName: user_id
          KeyType: HASH
      GlobalSecondaryIndexes:
        - IndexName: EmailIndex
          KeySchema:
            - AttributeName: email
              KeyType: HASH
          Projection:
            ProjectionType: ALL
        - IndexName: UsernameIndex
          KeySchema:
            - AttributeName: username
              KeyType: HASH
          Projection:
            ProjectionType: ALL

  SessionsTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub ${Environment}-sessions
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: session_id
          AttributeType: S
        - AttributeName: user_id
          AttributeType: S
      KeySchema:
        - AttributeName: session_id
          KeyType: HASH
      GlobalSecondaryIndexes:
        - IndexName: UserIDIndex
          KeySchema:
            - AttributeName: user_id
              KeyType: HASH
          Projection:
            ProjectionType: ALL
      TimeToLiveSpecification:
        Enabled: true
        AttributeName: expires_at

  PermissionsTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub ${Environment}-permissions
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: role_name
          AttributeType: S
        - AttributeName: permission
          AttributeType: S
      KeySchema:
        - AttributeName: role_name
          KeyType: HASH
        - AttributeName: permission
          KeyType: RANGE

Outputs:
  ApiUrl:
    Description: API Gateway endpoint URL
    Value: !Sub https://${ServerlessRestApi}.execute-api.${AWS::Region}.amazonaws.com/Prod/
```

### GitHub Actions Workflow
```yaml
# .github/workflows/deploy.yml
name: Deploy to AWS Lambda

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  AWS_REGION: us-east-1
  GO_VERSION: '1.21'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: ${{ env.GO_VERSION }}
      
      - name: Cache Go modules
        uses: actions/cache@v3
        with:
          path: ~/go/pkg/mod
          key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
          restore-keys: |
            ${{ runner.os }}-go-
      
      - name: Install dependencies
        run: go mod download
      
      - name: Run tests
        run: |
          go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
          go tool cover -func=coverage.txt
      
      - name: Run linter
        uses: golangci/golangci-lint-action@v3
        with:
          version: latest
      
      - name: Security scan
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec -fmt json -out gosec-report.json ./...

  build:
    needs: test
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: ${{ env.GO_VERSION }}
      
      - name: Build binary
        run: |
          GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
            -ldflags="-s -w" \
            -tags lambda.norpc \
            -o bootstrap cmd/lambda/main.go
      
      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: lambda-binary
          path: bootstrap

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3
      
      - name: Download artifact
        uses: actions/download-artifact@v3
        with:
          name: lambda-binary
      
      - name: Setup SAM CLI
        uses: aws-actions/setup-sam@v2
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Deploy to AWS
        run: |
          sam deploy \
            --stack-name gofiber-app-${{ github.ref_name }} \
            --s3-bucket ${{ secrets.SAM_BUCKET }} \
            --parameter-overrides \
              Environment=${{ github.ref_name == 'main' && 'prod' || 'staging' }} \
            --capabilities CAPABILITY_IAM \
            --no-fail-on-empty-changeset
      
      - name: Get API endpoint
        run: |
          aws cloudformation describe-stacks \
            --stack-name gofiber-app-${{ github.ref_name }} \
            --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
            --output text
```

### Makefile
```makefile
# Makefile
.PHONY: build clean deploy test

BINARY_NAME=bootstrap
LAMBDA_PACKAGE=lambda-deployment.zip

build:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
		-ldflags="-s -w" \
		-tags lambda.norpc \
		-o $(BINARY_NAME) cmd/lambda/main.go

test:
	go test -v -race -coverprofile=coverage.txt ./...
	go tool cover -html=coverage.txt -o coverage.html

lint:
	golangci-lint run ./...

security:
	gosec ./...

run-local:
	sam local start-api --env-vars env.json

deploy-dev:
	sam deploy --config-env dev

deploy-staging:
	sam deploy --config-env staging

deploy-prod:
	sam deploy --config-env prod

clean:
	rm -f $(BINARY_NAME) $(LAMBDA_PACKAGE)
	rm -f coverage.txt coverage.html

# DynamoDB local testing
dynamo-local:
	docker run -p 8000:8000 amazon/dynamodb-local

seed-data:
	go run scripts/seed.go
```

### SAM Configuration
```toml
# deployments/samconfig.toml
version = 0.1

[default]
[default.global]
[default.global.parameters]
stack_name = "gofiber-app"

[default.build]
[default.build.parameters]
cached = true
parallel = true

[default.deploy]
[default.deploy.parameters]
capabilities = "CAPABILITY_IAM"
confirm_changeset = true
resolve_s3 = true

[dev]
[dev.deploy]
[dev.deploy.parameters]
stack_name = "gofiber-app-dev"
s3_prefix = "gofiber-app-dev"
region = "us-east-1"
parameter_overrides = "Environment=dev"

[staging]
[staging.deploy]
[staging.deploy.parameters]
stack_name = "gofiber-app-staging"
s3_prefix = "gofiber-app-staging"
region = "us-east-1"
parameter_overrides = "Environment=staging"

[prod]
[prod.deploy]
[prod.deploy.parameters]
stack_name = "gofiber-app-prod"
s3_prefix = "gofiber-app-prod"
region = "us-east-1"
parameter_overrides = "Environment=prod"
confirm_changeset = true
```

---

## Usage Instructions for Claude Code

### Standard Project Generation Prompt
```markdown
Create a new AWS Lambda application using this exact specification:

## Project Requirements
- Use Go 1.21+ with GoFiber v2 framework
- Deploy to AWS Lambda with API Gateway
- Use fiber-lambda adapter for Lambda integration
- Implement cookie-based sessions stored in DynamoDB
- Create user authentication with username/password
- Store user permissions in DynamoDB
- Enable verbose logging for all operations
- Deploy using SAM and GitHub Actions

## Implementation Guidelines
1. Follow the PROJECT_STANDARDS.md exactly
2. Implement complete error handling
3. Add verbose logging to every function
4. Create comprehensive tests (minimum 80% coverage)
5. Include security headers middleware
6. Implement RBAC with permissions
7. Use prepared DynamoDB queries
8. Optimize for Lambda cold starts

## Required Endpoints
- POST /api/v1/register - User registration
- POST /api/v1/login - User authentication
- POST /api/v1/logout - Session termination
- GET /api/v1/profile - Get user profile (authenticated)
- PUT /api/v1/profile - Update profile (authenticated)
- GET /api/v1/admin/users - List users (admin only)
- GET /health - Health check

## Deliverables
1. Complete Go application code
2. Unit and integration tests
3. SAM template (template.yaml)
4. GitHub Actions workflow
5. Makefile with all commands
6. README with setup instructions
7. Environment variable documentation
```

---

## Environment Variables

### Required Environment Variables
```bash
# Lambda Environment
SERVICE_NAME=gofiber-app
ENVIRONMENT=dev|staging|prod
VERSION=1.0.0
LOG_LEVEL=VERBOSE

# AWS Resources
AWS_REGION=us-east-1
USERS_TABLE=${ENVIRONMENT}-users
SESSIONS_TABLE=${ENVIRONMENT}-sessions
PERMISSIONS_TABLE=${ENVIRONMENT}-permissions

# Application Settings
SESSION_DURATION=24h
COOKIE_SECURE=true
COOKIE_HTTPONLY=true
COOKIE_SAMESITE=Strict

# Optional
MFA_ENABLED=false
PASSWORD_MIN_LENGTH=12
MAX_LOGIN_ATTEMPTS=5
```

---

## GitHub Secrets and Variables

### Required GitHub Secrets (Repository Settings → Secrets and Variables → Actions)

#### Production Secrets
```
AWS_ACCESS_KEY_ID
  - Description: AWS access key for deployment
  - Type: Secret
  - Required for: Deployment to AWS
  - Scope: Production, Staging, Dev
  - Rotation: Every 90 days

AWS_SECRET_ACCESS_KEY
  - Description: AWS secret access key
  - Type: Secret
  - Required for: Deployment to AWS
  - Scope: Production, Staging, Dev
  - Rotation: Every 90 days

SAM_BUCKET
  - Description: S3 bucket name for SAM artifacts
  - Type: Secret
  - Required for: SAM deployment
  - Example: my-sam-deployment-bucket
  - Scope: Per environment

JWT_SECRET
  - Description: Secret key for JWT token signing
  - Type: Secret
  - Required for: Authentication
  - Length: Minimum 32 characters, cryptographically random
  - Rotation: Every 180 days
  - Scope: Per environment (prod, staging, dev)

ENCRYPTION_KEY
  - Description: 32-byte key for data encryption at rest
  - Type: Secret
  - Required for: Sensitive data encryption
  - Length: Exactly 32 bytes (256-bit)
  - Rotation: Annual with migration strategy
  - Scope: Per environment

GITHUB_TOKEN
  - Description: GitHub personal access token for API access
  - Type: Secret
  - Required for: GitHub Actions workflow, repository operations
  - Scopes: repo, workflow
  - Rotation: Every 90 days

WEBHOOK_SECRET
  - Description: Secret for validating incoming webhooks
  - Type: Secret
  - Required for: External integrations
  - Length: Minimum 32 characters
  - Rotation: Every 180 days
```

#### Optional Secrets (Based on Features)
```
SMTP_PASSWORD
  - Description: SMTP server password for email
  - Type: Secret
  - Required for: Email notifications, password resets
  - Required when: Email features enabled

SES_ACCESS_KEY / SES_SECRET_KEY
  - Description: AWS SES credentials
  - Type: Secret
  - Required for: Email via AWS SES
  - Alternative to: SMTP configuration

DATADOG_API_KEY
  - Description: Datadog API key
  - Type: Secret
  - Required for: APM and monitoring integration
  - Optional: Only if using Datadog

SLACK_WEBHOOK_URL
  - Description: Slack webhook for deployment notifications
  - Type: Secret
  - Required for: Deployment alerts
  - Optional: Notification integrations

SONARCLOUD_TOKEN
  - Description: SonarCloud token for code analysis
  - Type: Secret
  - Required for: Code quality scanning
  - Optional: CI/CD enhancement
```

### GitHub Repository Variables (Repository Settings → Secrets and Variables → Actions → Variables)

```
AWS_REGION
  - Description: Primary AWS region
  - Type: Variable
  - Default: us-east-1
  - Scope: All environments

SERVICE_NAME
  - Description: Base service name
  - Type: Variable
  - Example: gofiber-app
  - Scope: All environments

ENVIRONMENT_DEV
  - Description: Development environment identifier
  - Type: Variable
  - Default: dev

ENVIRONMENT_STAGING
  - Description: Staging environment identifier
  - Type: Variable
  - Default: staging

ENVIRONMENT_PROD
  - Description: Production environment identifier
  - Type: Variable
  - Default: prod

GO_VERSION
  - Description: Go version for builds
  - Type: Variable
  - Default: "1.21"
  - Update: When upgrading Go version

LAMBDA_TIMEOUT
  - Description: Lambda function timeout in seconds
  - Type: Variable
  - Default: "30"
  - Per environment: prod=30, dev=60

LAMBDA_MEMORY
  - Description: Lambda function memory in MB
  - Type: Variable
  - Default: "512"
  - Per environment: prod=1024, dev=512

LOG_LEVEL
  - Description: Logging level
  - Type: Variable
  - Default: VERBOSE
  - Per environment: prod=INFO, staging=DEBUG, dev=VERBOSE

SESSION_DURATION
  - Description: Session cookie duration
  - Type: Variable
  - Default: "24h"

PASSWORD_MIN_LENGTH
  - Description: Minimum password length
  - Type: Variable
  - Default: "12"

MAX_LOGIN_ATTEMPTS
  - Description: Maximum failed login attempts
  - Type: Variable
  - Default: "5"

CORS_ORIGINS
  - Description: Allowed CORS origins (comma-separated)
  - Type: Variable
  - Per environment:
    - prod: https://app.example.com
    - staging: https://staging.example.com
    - dev: http://localhost:3000

ENABLE_MFA
  - Description: Enable MFA feature flag
  - Type: Variable
  - Default: "false"
  - Per environment: prod=true, staging=true, dev=false

RATE_LIMIT_MAX_REQUESTS
  - Description: Max requests per window
  - Type: Variable
  - Default: "100"
  - Per environment: prod=100, dev=1000
```

### Environment-Specific Secrets Naming Convention
```
Format: {SECRET_NAME}_{ENVIRONMENT}

Examples:
  JWT_SECRET_PROD
  JWT_SECRET_STAGING
  JWT_SECRET_DEV

  AWS_ACCESS_KEY_ID_PROD
  AWS_ACCESS_KEY_ID_STAGING
  AWS_ACCESS_KEY_ID_DEV
```

### Secret Management Best Practices

1. **Never Commit Secrets**
   - Use .gitignore for .env files
   - Scan commits with git-secrets or similar tools
   - Use pre-commit hooks to prevent secret leaks

2. **Secret Rotation Policy**
   - AWS Credentials: Every 90 days
   - JWT Secrets: Every 180 days
   - Encryption Keys: Annually with migration
   - Document rotation dates in secure password manager

3. **Access Control**
   - Limit who can view/edit secrets
   - Use GitHub environment protection rules
   - Require reviews for production deployments
   - Enable audit logging

4. **Secret Generation**
   ```bash
   # Generate cryptographically secure secrets
   openssl rand -base64 32  # For JWT_SECRET
   openssl rand -hex 32     # For ENCRYPTION_KEY
   ```

5. **Testing Secrets**
   - Use separate secrets for each environment
   - Never use production secrets in dev/staging
   - Use mock/dummy values for local development

6. **Monitoring**
   - Enable AWS CloudTrail for secret access
   - Alert on secret rotation failures
   - Monitor for unauthorized access attempts

---

This comprehensive standard document provides Claude Code with all the necessary specifications to build consistent AWS Lambda applications with GoFiber, complete session management, authentication, and deployment automation. The verbose logging ensures full observability for your 24x7 SRE team, while the DynamoDB-based session and user management provides a scalable, serverless solution.
