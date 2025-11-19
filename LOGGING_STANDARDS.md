# Observability and Logging Standards

## Overview
This document defines standardized logging practices for AWS Lambda Go/Fiber applications to ensure consistent, human-readable observability across all services.

**Version:** 1.0
**Last Updated:** November 19, 2025

---

## Core Principles

1. **Human-First**: Logs must be immediately understandable by engineers without referring to code
2. **Structured**: Use consistent JSON format for machine parsing and analysis
3. **Contextual**: Every log includes who, what, why, where, and when
4. **Actionable**: Logs should guide incident response and debugging
5. **Concise**: Human-readable messages in one sentence or less

---

## Standard Log Fields

### Required Fields (Every Log Entry)

```go
type StandardLogFields struct {
    // Machine-readable fields
    Timestamp   string `json:"timestamp"`    // RFC3339 format
    Level       string `json:"level"`        // debug, info, warn, error
    Service     string `json:"service"`      // gofiber-app
    Environment string `json:"environment"`  // dev, staging, prod
    Version     string `json:"version"`      // 1.0.0

    // Human-readable fields
    Who         string `json:"who"`          // User/system identifier
    What        string `json:"what"`         // Action being performed
    Why         string `json:"why"`          // Reason/purpose (1 sentence max)
    Where       string `json:"where"`        // System/component name

    // Context fields
    RequestID   string `json:"request_id"`   // Trace ID
    UserID      string `json:"user_id,omitempty"`
    SessionID   string `json:"session_id,omitempty"`
    IPAddress   string `json:"ip_address,omitempty"`

    // Technical details (nested for clarity)
    Details     map[string]interface{} `json:"details,omitempty"`
}
```

### Field Definitions

#### `who` - Actor/Subject (Required)
**Format:** `{entity_type}:{identifier}` or human-readable name
**Purpose:** Identifies who/what initiated the action
**Max Length:** 50 characters

**Examples:**
```
who: "user:john@example.com"
who: "user:user_123456"
who: "system:scheduler"
who: "service:payment-api"
who: "admin:support_team"
who: "apikey:prod_key_789"
who: "anonymous"
```

#### `what` - Action/Operation (Required)
**Format:** `{verb} {object}` in past tense
**Purpose:** What action was performed
**Max Length:** 60 characters

**Examples:**
```
what: "created user account"
what: "validated session token"
what: "updated user profile"
what: "deleted API key"
what: "sent password reset email"
what: "queried users table"
what: "processed webhook payload"
what: "failed login attempt"
```

#### `why` - Purpose/Reason (Required)
**Format:** Single sentence explaining business/technical reason
**Purpose:** Provides context for the action
**Max Length:** 100 characters

**Examples:**
```
why: "user registration requested via signup form"
why: "session expired after 24 hours"
why: "admin requested user data export"
why: "detected 5 failed login attempts"
why: "API key rotation policy triggered"
why: "scheduled daily backup job"
why: "webhook received from payment provider"
why: "security audit requirement"
```

#### `where` - System/Component (Required)
**Format:** `{system}:{component}` or human-readable name
**Purpose:** Identifies which part of the system is logging
**Max Length:** 50 characters

**Examples:**
```
where: "auth-service:login-handler"
where: "user-service:profile-updater"
where: "database:dynamodb-users"
where: "middleware:session-validator"
where: "external:payment-gateway"
where: "scheduler:backup-job"
where: "api:webhook-receiver"
```

---

## Log Level Guidelines

### DEBUG
**When:** Development/troubleshooting, verbose operational details
**Audience:** Developers debugging issues
**Production:** Only enabled for specific troubleshooting

```go
Logger.Debug().
    Str("who", "user:john@example.com").
    Str("what", "validated input fields").
    Str("why", "registration form submitted").
    Str("where", "auth-service:registration-handler").
    Interface("details", map[string]interface{}{
        "fields_validated": []string{"email", "username", "password"},
        "validation_duration_ms": 12,
    }).
    Msg("Input validation completed")
```

### INFO
**When:** Normal operations, significant business events
**Audience:** Operations team, business stakeholders
**Production:** Always enabled

```go
Logger.Info().
    Str("who", "user:john@example.com").
    Str("what", "created user account").
    Str("why", "new user registration completed").
    Str("where", "user-service:account-creator").
    Str("user_id", "usr_abc123").
    Msg("User account created successfully")
```

### WARN
**When:** Recoverable errors, degraded functionality, suspicious activity
**Audience:** Operations team (may trigger alerts)
**Production:** Always enabled, monitored

```go
Logger.Warn().
    Str("who", "user:suspicious@example.com").
    Str("what", "failed login attempt").
    Str("why", "incorrect password provided (attempt 3/5)").
    Str("where", "auth-service:login-handler").
    Str("ip_address", "192.168.1.100").
    Int("failed_attempts", 3).
    Msg("Failed login - approaching lockout threshold")
```

### ERROR
**When:** Errors requiring investigation, failed operations
**Audience:** Operations team (triggers alerts)
**Production:** Always enabled, alerted

```go
Logger.Error().
    Str("who", "system:payment-processor").
    Str("what", "failed to process payment").
    Str("why", "external payment gateway timeout").
    Str("where", "payment-service:charge-handler").
    Err(err).
    Interface("details", map[string]interface{}{
        "transaction_id": "txn_xyz789",
        "amount": 99.99,
        "gateway": "stripe",
        "timeout_seconds": 30,
    }).
    Msg("Payment processing failed - gateway timeout")
```

---

## Implementation Examples

### 1. HTTP Request Logging

```go
// internal/api/middleware/logging.go
package middleware

import (
    "time"
    "github.com/gofiber/fiber/v2"
    "yourapp/internal/utils"
)

func RequestLogger() fiber.Handler {
    return func(c *fiber.Ctx) error {
        start := time.Now()

        // Extract or generate request ID
        requestID := c.Get("X-Request-ID")
        if requestID == "" {
            requestID = uuid.New().String()
            c.Set("X-Request-ID", requestID)
        }

        // Determine who is making the request
        who := "anonymous"
        if user := c.Locals("user"); user != nil {
            if u, ok := user.(*models.User); ok {
                who = fmt.Sprintf("user:%s", u.Email)
            }
        } else if apiKey := c.Locals("api_key"); apiKey != nil {
            who = "apikey:service"
        }

        // Log incoming request
        utils.Logger.Info().
            Str("who", who).
            Str("what", fmt.Sprintf("received %s request", c.Method())).
            Str("why", "client API call initiated").
            Str("where", fmt.Sprintf("api:%s", c.Path())).
            Str("request_id", requestID).
            Str("method", c.Method()).
            Str("path", c.Path()).
            Str("ip_address", c.IP()).
            Str("user_agent", c.Get("User-Agent")).
            Msg("API request received")

        // Process request
        err := c.Next()

        // Calculate duration
        duration := time.Since(start)

        // Log response
        statusCode := c.Response().StatusCode()
        level := utils.Logger.Info()

        if statusCode >= 500 {
            level = utils.Logger.Error()
        } else if statusCode >= 400 {
            level = utils.Logger.Warn()
        }

        level.
            Str("who", who).
            Str("what", fmt.Sprintf("completed %s request", c.Method())).
            Str("why", fmt.Sprintf("returned HTTP %d", statusCode)).
            Str("where", fmt.Sprintf("api:%s", c.Path())).
            Str("request_id", requestID).
            Int("status_code", statusCode).
            Dur("duration_ms", duration).
            Int("response_size_bytes", len(c.Response().Body())).
            Msg("API request completed")

        return err
    }
}
```

### 2. Database Operation Logging

```go
// internal/database/repository/user_repository.go
package repository

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
    start := time.Now()

    utils.Logger.Debug().
        Str("who", "system:user-repository").
        Str("what", "creating user record").
        Str("why", "new user registration in progress").
        Str("where", "database:dynamodb-users").
        Str("table_name", r.tableName).
        Str("user_email", user.Email).
        Msg("Initiating user creation in DynamoDB")

    av, err := attributevalue.MarshalMap(user)
    if err != nil {
        utils.Logger.Error().
            Str("who", "system:user-repository").
            Str("what", "failed to marshal user data").
            Str("why", "DynamoDB attribute conversion error").
            Str("where", "database:dynamodb-users").
            Err(err).
            Msg("User creation failed - marshaling error")
        return fmt.Errorf("failed to marshal user: %w", err)
    }

    _, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
        TableName: aws.String(r.tableName),
        Item:      av,
        ConditionExpression: aws.String("attribute_not_exists(user_id)"),
    })

    duration := time.Since(start)

    if err != nil {
        utils.Logger.Error().
            Str("who", "system:user-repository").
            Str("what", "failed to create user").
            Str("why", "DynamoDB PutItem operation failed").
            Str("where", "database:dynamodb-users").
            Str("user_id", user.UserID).
            Dur("duration_ms", duration).
            Err(err).
            Msg("User creation failed - database error")
        return fmt.Errorf("failed to create user: %w", err)
    }

    utils.Logger.Info().
        Str("who", fmt.Sprintf("user:%s", user.Email)).
        Str("what", "created user record").
        Str("why", "user registration successful").
        Str("where", "database:dynamodb-users").
        Str("user_id", user.UserID).
        Dur("duration_ms", duration).
        Msg("User created successfully in DynamoDB")

    return nil
}
```

### 3. Authentication Flow Logging

```go
// internal/api/handlers/auth.go

func Login(c *fiber.Ctx) error {
    var req LoginRequest

    if err := c.BodyParser(&req); err != nil {
        utils.Logger.Warn().
            Str("who", "anonymous").
            Str("what", "failed to parse login request").
            Str("why", "malformed JSON in request body").
            Str("where", "auth-service:login-handler").
            Str("ip_address", c.IP()).
            Msg("Login request parsing failed")

        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request format",
        })
    }

    utils.Logger.Info().
        Str("who", fmt.Sprintf("user:%s", req.Email)).
        Str("what", "attempting login").
        Str("why", "user submitted login credentials").
        Str("where", "auth-service:login-handler").
        Str("ip_address", c.IP()).
        Msg("Login attempt initiated")

    // Validate credentials
    user, err := userService.ValidateCredentials(c.Context(), req.Email, req.Password)
    if err != nil {
        // Record security event
        securityService.RecordLoginAttempt(
            c.Context(),
            req.Email,
            c.IP(),
            c.Get("User-Agent"),
            false,
        )

        utils.Logger.Warn().
            Str("who", fmt.Sprintf("user:%s", req.Email)).
            Str("what", "failed login attempt").
            Str("why", "invalid credentials provided").
            Str("where", "auth-service:login-handler").
            Str("ip_address", c.IP()).
            Msg("Login failed - invalid credentials")

        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Invalid credentials",
        })
    }

    // Create session
    session, err := sessionService.Create(c.Context(), user)
    if err != nil {
        utils.Logger.Error().
            Str("who", fmt.Sprintf("user:%s", user.Email)).
            Str("what", "failed to create session").
            Str("why", "session creation service error").
            Str("where", "auth-service:session-creator").
            Str("user_id", user.UserID).
            Err(err).
            Msg("Login failed - session creation error")

        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to create session",
        })
    }

    // Set session cookie
    auth.SetSessionCookie(c, session.SessionID)

    utils.Logger.Info().
        Str("who", fmt.Sprintf("user:%s", user.Email)).
        Str("what", "logged in successfully").
        Str("why", "credentials validated and session created").
        Str("where", "auth-service:login-handler").
        Str("user_id", user.UserID).
        Str("session_id", session.SessionID).
        Str("ip_address", c.IP()).
        Msg("User login successful")

    return c.JSON(fiber.Map{
        "message": "Login successful",
        "user": user,
    })
}
```

### 4. External Service Integration Logging

```go
// internal/service/email_service.go

func (s *EmailService) SendPasswordResetEmail(ctx context.Context, user *models.User, resetToken string) error {
    utils.Logger.Info().
        Str("who", "system:email-service").
        Str("what", "sending password reset email").
        Str("why", "user requested password reset").
        Str("where", "external:smtp-server").
        Str("user_id", user.UserID).
        Str("recipient", user.Email).
        Msg("Initiating password reset email")

    message := s.buildPasswordResetEmail(user, resetToken)

    err := s.smtpClient.Send(ctx, message)
    if err != nil {
        utils.Logger.Error().
            Str("who", "system:email-service").
            Str("what", "failed to send password reset email").
            Str("why", "SMTP server connection failed").
            Str("where", "external:smtp-server").
            Str("user_id", user.UserID).
            Str("recipient", user.Email).
            Err(err).
            Msg("Password reset email failed")
        return err
    }

    utils.Logger.Info().
        Str("who", "system:email-service").
        Str("what", "sent password reset email").
        Str("why", "password reset request processed").
        Str("where", "external:smtp-server").
        Str("user_id", user.UserID).
        Str("recipient", user.Email).
        Msg("Password reset email sent successfully")

    return nil
}
```

### 5. Scheduled Job Logging

```go
// internal/jobs/cleanup_job.go

func (j *CleanupJob) Run(ctx context.Context) error {
    utils.Logger.Info().
        Str("who", "system:scheduler").
        Str("what", "started cleanup job").
        Str("why", "scheduled daily maintenance task").
        Str("where", "job:session-cleanup").
        Msg("Session cleanup job started")

    expiredSessions, err := j.sessionRepo.FindExpired(ctx)
    if err != nil {
        utils.Logger.Error().
            Str("who", "system:scheduler").
            Str("what", "failed to query expired sessions").
            Str("why", "database query error during cleanup").
            Str("where", "job:session-cleanup").
            Err(err).
            Msg("Cleanup job failed - query error")
        return err
    }

    utils.Logger.Info().
        Str("who", "system:scheduler").
        Str("what", "found expired sessions").
        Str("why", "preparing to delete stale data").
        Str("where", "job:session-cleanup").
        Int("expired_count", len(expiredSessions)).
        Msg("Expired sessions identified")

    deleted := 0
    for _, session := range expiredSessions {
        if err := j.sessionRepo.Delete(ctx, session.SessionID); err != nil {
            utils.Logger.Warn().
                Str("who", "system:scheduler").
                Str("what", "failed to delete session").
                Str("why", "database delete operation failed").
                Str("where", "job:session-cleanup").
                Str("session_id", session.SessionID).
                Err(err).
                Msg("Session deletion failed - continuing")
            continue
        }
        deleted++
    }

    utils.Logger.Info().
        Str("who", "system:scheduler").
        Str("what", "completed cleanup job").
        Str("why", "daily maintenance completed").
        Str("where", "job:session-cleanup").
        Int("deleted_count", deleted).
        Int("total_found", len(expiredSessions)).
        Msg("Session cleanup job completed")

    return nil
}
```

### 6. Security Event Logging

```go
// internal/service/security_service.go

func (s *SecurityService) RecordLoginAttempt(ctx context.Context, email, ipAddress, userAgent string, success bool) error {
    eventType := "login_success"
    who := fmt.Sprintf("user:%s", email)
    what := "logged in successfully"
    why := "valid credentials provided"

    if !success {
        eventType = "login_failed"
        what = "failed login attempt"
        why = "invalid credentials provided"
    }

    // Calculate risk score
    riskScore := s.calculateRiskScore(ctx, email, ipAddress, userAgent)

    utils.Logger.Info().
        Str("who", who).
        Str("what", what).
        Str("why", why).
        Str("where", "security:event-recorder").
        Str("ip_address", ipAddress).
        Int("risk_score", riskScore).
        Bool("success", success).
        Msg("Security event recorded")

    event := &models.SecurityEvent{
        EventID:   fmt.Sprintf("%s#%d", email, time.Now().UnixNano()),
        EventType: eventType,
        IPAddress: ipAddress,
        UserAgent: userAgent,
        Timestamp: time.Now(),
        RiskScore: riskScore,
        TTL:       time.Now().Add(90 * 24 * time.Hour).Unix(),
    }

    if err := s.eventRepo.Create(ctx, event); err != nil {
        utils.Logger.Error().
            Str("who", "system:security-service").
            Str("what", "failed to save security event").
            Str("why", "database write operation failed").
            Str("where", "security:event-recorder").
            Err(err).
            Msg("Security event recording failed")
        return err
    }

    // Check if account should be locked
    if !success && riskScore > 50 {
        utils.Logger.Warn().
            Str("who", who).
            Str("what", "detected suspicious activity").
            Str("why", "high risk score on failed login").
            Str("where", "security:threat-detector").
            Int("risk_score", riskScore).
            Str("ip_address", ipAddress).
            Msg("Suspicious activity detected - investigating")

        // Handle potential account lockout...
    }

    return nil
}
```

---

## Log Aggregation and Query Patterns

### CloudWatch Insights Queries

#### Find all failed login attempts for a user
```sql
fields @timestamp, who, what, why, ip_address, risk_score
| filter what = "failed login attempt"
| filter who = "user:john@example.com"
| sort @timestamp desc
| limit 100
```

#### Find high-risk security events
```sql
fields @timestamp, who, what, why, where, risk_score, ip_address
| filter risk_score > 70
| sort risk_score desc, @timestamp desc
| limit 50
```

#### Track API endpoint performance
```sql
fields @timestamp, where, duration_ms, status_code
| filter what like /completed.*request/
| stats avg(duration_ms) as avg_duration,
        max(duration_ms) as max_duration,
        count(*) as request_count
  by where
| sort avg_duration desc
```

#### Audit user actions
```sql
fields @timestamp, who, what, why, where, details
| filter who = "user:john@example.com"
| filter what in ["created user account", "updated user profile", "deleted API key"]
| sort @timestamp desc
```

---

## Log Message Formatting

### Message Template
```
{level} [{timestamp}] {who} {what} - {why} @ {where}
```

### Examples of Good Messages
```
INFO  [2025-11-19T10:30:45Z] user:john@example.com created user account - new user registration completed @ user-service:account-creator

WARN  [2025-11-19T10:31:22Z] user:suspicious@example.com failed login attempt - incorrect password (3/5) @ auth-service:login-handler

ERROR [2025-11-19T10:32:15Z] system:payment-processor failed to process payment - external gateway timeout @ payment-service:charge-handler

DEBUG [2025-11-19T10:33:01Z] apikey:prod_key_789 validated API key - service-to-service authentication @ middleware:api-key-validator
```

### Examples of Bad Messages (Don't Do This)
```
❌ INFO  User created
    Problem: Missing who, why, where

❌ ERROR Error occurred: database connection failed
    Problem: Not structured, missing context

❌ DEBUG Processing request with params: {...}
    Problem: Not human-readable, unclear purpose

❌ INFO  [USER_REGISTRATION_COMPLETE] uid=123 status=OK
    Problem: Machine-only format, not human-friendly
```

---

## Logger Utility Setup

```go
// internal/utils/logger.go
package utils

import (
    "os"
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
)

var Logger zerolog.Logger

func InitLogger(level string) {
    zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

    // Set log level
    switch level {
    case "DEBUG", "VERBOSE":
        zerolog.SetGlobalLevel(zerolog.DebugLevel)
    case "INFO":
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
    case "WARN":
        zerolog.SetGlobalLevel(zerolog.WarnLevel)
    case "ERROR":
        zerolog.SetGlobalLevel(zerolog.ErrorLevel)
    default:
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
    }

    // Configure logger with standard fields
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
        Str("log_level", level).
        Msg("Logger initialized successfully")
}

// Helper to create structured log event
type LogEvent struct {
    who   string
    what  string
    why   string
    where string
}

func NewLogEvent(who, what, why, where string) *LogEvent {
    return &LogEvent{
        who:   who,
        what:  what,
        why:   why,
        where: where,
    }
}

func (e *LogEvent) Info() *zerolog.Event {
    return Logger.Info().
        Str("who", e.who).
        Str("what", e.what).
        Str("why", e.why).
        Str("where", e.where)
}

func (e *LogEvent) Debug() *zerolog.Event {
    return Logger.Debug().
        Str("who", e.who).
        Str("what", e.what).
        Str("why", e.why).
        Str("where", e.where)
}

func (e *LogEvent) Warn() *zerolog.Event {
    return Logger.Warn().
        Str("who", e.who).
        Str("what", e.what).
        Str("why", e.why).
        Str("where", e.where)
}

func (e *LogEvent) Error() *zerolog.Event {
    return Logger.Error().
        Str("who", e.who).
        Str("what", e.what).
        Str("why", e.why).
        Str("where", e.where)
}

// Usage example:
// utils.NewLogEvent(
//     "user:john@example.com",
//     "updated profile",
//     "user submitted profile changes",
//     "user-service:profile-handler",
// ).Info().Msg("Profile updated successfully")
```

---

## Testing Logs

### Unit Test Example
```go
// internal/service/user_service_test.go
func TestUserCreation_Logging(t *testing.T) {
    // Capture logs
    var buf bytes.Buffer
    testLogger := zerolog.New(&buf)
    utils.Logger = testLogger

    // Create user
    service := NewUserService(mockRepo)
    _, err := service.CreateUser(context.Background(), &CreateUserRequest{
        Email: "test@example.com",
        Username: "testuser",
    })

    require.NoError(t, err)

    // Verify log output
    logOutput := buf.String()

    assert.Contains(t, logOutput, `"who":"user:test@example.com"`)
    assert.Contains(t, logOutput, `"what":"created user account"`)
    assert.Contains(t, logOutput, `"why":"new user registration completed"`)
    assert.Contains(t, logOutput, `"where":"user-service:account-creator"`)
}
```

---

## Checklist for Implementation

### Before Merging Code
- [ ] Every log has `who`, `what`, `why`, `where` fields
- [ ] `why` field is one sentence or less
- [ ] Log level is appropriate (DEBUG/INFO/WARN/ERROR)
- [ ] Sensitive data is not logged (passwords, tokens, SSNs)
- [ ] Error logs include `Err(err)` field
- [ ] Request logs include `request_id`
- [ ] Database operations log duration
- [ ] External service calls log endpoint and why
- [ ] Human-readable message is clear without code context

### Code Review Checklist
- [ ] Logs follow standard field format
- [ ] Log messages are grammatically correct
- [ ] Technical details are in `details` field, not in message
- [ ] No redundant or duplicate logs
- [ ] Logs provide value for debugging/monitoring

---

## Quick Reference

### Command for Developers
```bash
# When adding a log, ask yourself:
# 1. WHO initiated this action? (user, system, service, apikey)
# 2. WHAT action was performed? (verb + object, past tense)
# 3. WHY did this happen? (business/technical reason, max 100 chars)
# 4. WHERE in the system? (service:component)

# Template:
Logger.Info().
    Str("who", "user:john@example.com").
    Str("what", "updated profile picture").
    Str("why", "user uploaded new avatar image").
    Str("where", "user-service:profile-handler").
    Msg("Profile picture updated")
```

### Field Character Limits
- `who`: 50 characters max
- `what`: 60 characters max
- `why`: 100 characters max (ONE sentence)
- `where`: 50 characters max
- `message`: Should match `what` field in natural language

---

## Compliance and Retention

- **Audit Logs**: 7 years (compliance requirement)
- **Application Logs**: 90 days in CloudWatch
- **Error Logs**: 1 year in CloudWatch
- **Debug Logs**: 7 days in CloudWatch (dev/staging only)

---

**Document Owner:** DevOps/SRE Team
**Review Schedule:** Quarterly
**Next Review:** February 2026
