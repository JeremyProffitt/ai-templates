# AWS Lambda Go/Fiber Application Generator

**For:** Claude Code CLI and AI-Assisted Development
**Version:** 1.0
**Last Updated:** November 19, 2025

---

## Quick Context (3-Minute Read)

**What This Is:**
Production-ready templates for building AWS Lambda applications with Go, Fiber framework, and DynamoDB following Ally Financial SRE/DevSecOps standards.

**Architecture:**
```
API Gateway → Lambda (GoFiber) → DynamoDB
                ↓
         CloudWatch Logs
```

**Key Characteristics:**
- Serverless, stateless execution
- Cookie-based sessions in DynamoDB
- Verbose structured logging (who/what/why/where)
- Security-first design
- 24x7 SRE support model

---

## Essential Requirements (Priority Order)

### 1. PROJECT STRUCTURE [REQUIRED]

```
/
├── cmd/lambda/main.go           # Lambda handler
├── internal/
│   ├── api/
│   │   ├── handlers/            # HTTP handlers
│   │   ├── middleware/          # Middleware
│   │   └── routes/              # Route setup
│   ├── auth/                    # Auth logic
│   ├── config/                  # Configuration
│   ├── database/
│   │   ├── models/              # Data models
│   │   └── repository/          # Data access
│   ├── service/                 # Business logic
│   └── utils/                   # Utilities
├── deployments/
│   ├── template.yaml            # SAM template
│   └── samconfig.toml          # SAM config
├── .github/workflows/deploy.yml # CI/CD
└── Makefile                     # Build commands
```

→ Full details: [standards/ARCHITECTURE_STANDARDS.md](./standards/ARCHITECTURE_STANDARDS.md)

---

### 2. LOGGING PATTERN [CRITICAL - ALWAYS ENFORCE]

**EVERY log MUST include four fields:**

```go
Logger.Info().
    Str("who", "user:john@example.com").      // Actor (max 50 chars)
    Str("what", "created user account").      // Action, past tense (max 60 chars)
    Str("why", "user registration completed"). // Business reason, ONE sentence (max 100 chars)
    Str("where", "auth-service:register").    // Component (max 50 chars)
    Msg("User registered successfully")
```

**Field Rules:**
- `who`: Format `{type}:{identifier}` - Examples: `user:email`, `system:scheduler`, `apikey:prod_key`
- `what`: Past tense verb + object - Examples: `created user`, `validated session`, `sent email`
- `why`: Business reason in ONE sentence - NOT technical details
- `where`: Format `{service}:{component}` - Examples: `auth-service:login`, `database:dynamodb-users`

**Common Mistakes to Avoid:**
- ❌ Missing any of the four fields
- ❌ `why` is too technical: "function returned successfully"
- ❌ `why` is too long: More than 100 characters or multiple sentences
- ❌ Not human-readable: `op=GET_ITEM tbl=usr`

→ Full specification: [standards/LOGGING_STANDARDS.md](./standards/LOGGING_STANDARDS.md)
→ Quick reference: [reference/LOGGING_QUICK_REFERENCE.md](./reference/LOGGING_QUICK_REFERENCE.md)

---

### 3. AUTHENTICATION & SESSION MANAGEMENT

**Session Storage:**
- DynamoDB table with TTL (24-hour expiration)
- Cookie-based (Secure, HTTPOnly, SameSite=Strict)
- Session ID is cryptographically random (32 bytes)

**Password Security:**
- bcrypt hashing (cost 14)
- Minimum 12 characters
- Require: uppercase, lowercase, number, special character
- Check against HaveIBeenPwned breach database

**RBAC:**
- Roles: user, editor, admin
- Permissions stored in DynamoDB
- Middleware validates permissions on protected routes

```go
// Authentication middleware
protected := app.Group("/api/v1", middleware.RequireAuth())
admin := app.Group("/api/v1/admin",
    middleware.RequireAuth(),
    middleware.RequirePermission("admin"))
```

→ See: [standards/SECURITY_STANDARDS.md](./standards/SECURITY_STANDARDS.md)

---

### 4. ERROR HANDLING PATTERN [REQUIRED]

**Never expose internal errors to clients:**

```go
func Handler(c *fiber.Ctx) error {
    result, err := service.DoSomething(c.Context())
    if err != nil {
        // Log full error with context
        Logger.Error().
            Str("who", "system:service").
            Str("what", "failed operation").
            Str("why", "database connection timeout").
            Str("where", "service:handler").
            Err(err).  // Full error for debugging
            Msg("Operation failed")

        // Return generic error to client
        return c.Status(500).JSON(fiber.Map{
            "error": "An error occurred",
        })
    }
    return c.JSON(result)
}
```

**All functions must:**
- Wrap operations in error handling
- Log errors with who/what/why/where
- Return appropriate HTTP status codes
- Never leak stack traces or internal details

→ See: [standards/CODING_STANDARDS.md](./standards/CODING_STANDARDS.md)

---

### 5. INPUT VALIDATION [SECURITY CRITICAL]

**Validate ALL inputs:**

```go
type RegisterRequest struct {
    Email    string `json:"email" validate:"required,email,max=255"`
    Username string `json:"username" validate:"required,username,no_sql_injection"`
    Password string `json:"password" validate:"required,strong_password"`
    Name     string `json:"name" validate:"required,min=2,max=100,safe_string"`
}

func Register(c *fiber.Ctx) error {
    var req RegisterRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
    }

    // Validate
    if err := utils.ValidateStruct(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": err.Error()})
    }

    // Sanitize
    req.Email = strings.ToLower(strings.TrimSpace(req.Email))
    req.Name = utils.SanitizeHTML(req.Name)

    // Process...
}
```

**Required validations:**
- Email format
- SQL injection patterns
- XSS patterns
- Length limits
- Type safety

→ See: [guides/SECURITY_IMPLEMENTATION.md](./guides/SECURITY_IMPLEMENTATION.md#input-validation)

---

## Code Generation Templates

### Lambda Handler Template

```go
// cmd/lambda/main.go
package main

import (
    "context"
    "github.com/aws/aws-lambda-go/events"
    "github.com/aws/aws-lambda-go/lambda"
    fiberadapter "github.com/awslabs/aws-lambda-go-api-proxy/fiber"
    "github.com/gofiber/fiber/v2"
)

var fiberLambda *fiberadapter.FiberLambda

func init() {
    Logger.Info().
        Str("who", "system:lambda-runtime").
        Str("what", "initializing Lambda function").
        Str("why", "cold start for new container").
        Str("where", "lambda:init").
        Msg("Lambda initialization started")

    // Initialize services
    config := config.Load()
    database.InitDynamoDB(config)

    // Setup Fiber app
    app := fiber.New(fiber.Config{
        ErrorHandler: utils.CustomErrorHandler,
    })
    routes.Setup(app)

    fiberLambda = fiberadapter.New(app)
}

func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
    return fiberLambda.ProxyWithContext(ctx, req)
}

func main() {
    lambda.Start(Handler)
}
```

### Handler Template

```go
func HandlerName(c *fiber.Ctx) error {
    // 1. Get user if authenticated
    user := c.Locals("user").(*models.User)

    // 2. Parse request
    var req RequestType
    if err := c.BodyParser(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
    }

    // 3. Validate
    if err := utils.ValidateStruct(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": err.Error()})
    }

    // 4. Call service
    result, err := service.Method(c.Context(), &req)
    if err != nil {
        Logger.Error().
            Str("who", fmt.Sprintf("user:%s", user.Email)).
            Str("what", "failed operation").
            Str("why", "service error occurred").
            Str("where", "handlers:handler-name").
            Err(err).
            Msg("Operation failed")
        return c.Status(500).JSON(fiber.Map{"error": "Internal error"})
    }

    // 5. Log and return
    Logger.Info().
        Str("who", fmt.Sprintf("user:%s", user.Email)).
        Str("what", "completed operation").
        Str("why", "user request processed successfully").
        Str("where", "handlers:handler-name").
        Msg("Operation completed")

    return c.JSON(result)
}
```

### Middleware Template

```go
func MiddlewareName() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Middleware logic with logging
        Logger.Debug().
            Str("who", "system:middleware").
            Str("what", "processing request").
            Str("why", "middleware chain execution").
            Str("where", "middleware:name").
            Msg("Middleware processing")

        // Process
        if err := doSomething(); err != nil {
            return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
        }

        return c.Next()
    }
}
```

---

## Critical Don'ts (NEVER DO THESE)

- ❌ **Never log passwords, tokens, API keys, or PII**
- ❌ **Never skip who/what/why/where in logs**
- ❌ **Never expose internal errors to API clients**
- ❌ **Never use local file storage (Lambda is ephemeral)**
- ❌ **Never hardcode configuration values**
- ❌ **Never create DynamoDB client on each request (reuse from init)**
- ❌ **Never ignore context cancellation**
- ❌ **Never skip input validation**
- ❌ **Never commit secrets to git**
- ❌ **Never use HTTP (always HTTPS with TLS 1.2+)**

---

## File Generation Checklist

When generating code, ensure:

### Structure
- [ ] Follows project structure exactly
- [ ] All files in correct directories
- [ ] Proper package names

### Logging
- [ ] Every log has who/what/why/where
- [ ] `why` field is business reason (not technical)
- [ ] `why` field is max 100 characters, one sentence
- [ ] No sensitive data in logs

### Security
- [ ] Input validation on all endpoints
- [ ] Error handling implemented
- [ ] No secrets in code
- [ ] Security headers middleware added
- [ ] CORS configured properly

### Code Quality
- [ ] Tests included (min 80% coverage)
- [ ] Error handling on all operations
- [ ] Context propagated through calls
- [ ] Proper HTTP status codes

### Lambda Specific
- [ ] Heavy initialization in init()
- [ ] DynamoDB client reused
- [ ] No local file operations
- [ ] Timeout configured (30s)

---

## Environment Variables Required

```bash
# Service
SERVICE_NAME=gofiber-app
ENVIRONMENT=dev|staging|prod
VERSION=1.0.0
LOG_LEVEL=VERBOSE

# AWS
AWS_REGION=us-east-1
USERS_TABLE=${ENVIRONMENT}-users
SESSIONS_TABLE=${ENVIRONMENT}-sessions

# Security (from secrets manager)
JWT_SECRET=${SECRET}
ENCRYPTION_KEY=${SECRET}

# Session
SESSION_DURATION=24h
COOKIE_SECURE=true
COOKIE_HTTPONLY=true
COOKIE_SAMESITE=Strict

# Rate Limiting
MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW=15m
```

→ See: [config/.env.example](./config/.env.example)

---

## Quick Start for Generation

1. **Read this file (GENERATION_MASTER.md)** for essentials
2. **Follow logging pattern** (who/what/why/where) - most important!
3. **Use templates above** for consistent code structure
4. **Reference detailed docs** when needed:
   - Architecture: [standards/ARCHITECTURE_STANDARDS.md](./standards/ARCHITECTURE_STANDARDS.md)
   - Coding: [standards/CODING_STANDARDS.md](./standards/CODING_STANDARDS.md)
   - Security: [standards/SECURITY_STANDARDS.md](./standards/SECURITY_STANDARDS.md)
   - Logging: [standards/LOGGING_STANDARDS.md](./standards/LOGGING_STANDARDS.md)
   - Database: [standards/DATABASE_STANDARDS.md](./standards/DATABASE_STANDARDS.md)
5. **Check against checklist** before completing

---

## Common Use Cases

### Generate New Application
```
User: "Generate a new Lambda API following ai-templates"
→ Read: GENERATION_MASTER.md
→ Create: Full project structure with all files
→ Ensure: All logging follows who/what/why/where pattern
```

### Add Feature
```
User: "Add API key authentication"
→ Read: GENERATION_MASTER.md + guides/SECURITY_IMPLEMENTATION.md
→ Implement: API key service + middleware
→ Ensure: Logging and error handling included
```

### Fix/Improve Code
```
User: "Fix logging to match standards"
→ Read: reference/LOGGING_QUICK_REFERENCE.md
→ Update: All logs to include who/what/why/where
→ Validate: Against checklist
```

---

## Reference Documents

### For Code Generation (AI)
- **This file**: GENERATION_MASTER.md (you are here)
- **Logging Quick Ref**: [reference/LOGGING_QUICK_REFERENCE.md](./reference/LOGGING_QUICK_REFERENCE.md)
- **Security Guide**: [guides/SECURITY_IMPLEMENTATION.md](./guides/SECURITY_IMPLEMENTATION.md)

### For Detailed Specifications
- **Architecture**: [standards/ARCHITECTURE_STANDARDS.md](./standards/ARCHITECTURE_STANDARDS.md)
- **Coding**: [standards/CODING_STANDARDS.md](./standards/CODING_STANDARDS.md)
- **Security**: [standards/SECURITY_STANDARDS.md](./standards/SECURITY_STANDARDS.md)
- **Logging**: [standards/LOGGING_STANDARDS.md](./standards/LOGGING_STANDARDS.md)
- **Database**: [standards/DATABASE_STANDARDS.md](./standards/DATABASE_STANDARDS.md)
- **Deployment**: [standards/DEPLOYMENT_STANDARDS.md](./standards/DEPLOYMENT_STANDARDS.md)

### For Implementation Help
- **Full Standards**: PROJECT_STANDARDS.md (comprehensive reference)
- **Generation Template**: CLAUDE_CODE_PROMPT.md (user-facing template)

---

## Success Criteria

Generated code must:
1. ✅ Compile without errors
2. ✅ Pass all tests (80%+ coverage)
3. ✅ Include who/what/why/where in ALL logs
4. ✅ Handle all errors gracefully
5. ✅ Validate all inputs
6. ✅ Follow project structure exactly
7. ✅ Include security headers
8. ✅ Use DynamoDB for all state
9. ✅ Optimize for Lambda (init in init())
10. ✅ Be production-ready

---

**Remember:** This is production code for a 24x7 SRE team. Quality and observability are paramount!

**Version:** 1.0
**Maintainer:** DevOps/SRE Team
**Size:** ~18KB (optimized for Claude Code context window)
