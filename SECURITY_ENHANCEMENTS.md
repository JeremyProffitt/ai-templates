# Security Enhancements Implementation Guide

## Overview
This document provides detailed implementation guidance for the selected security enhancements for the AWS Lambda Go/Fiber application template.

**Generated:** November 19, 2025
**Version:** 1.0
**Status:** Implementation Ready

---

## Selected Security Enhancements

### 1. Account Lockout and Suspicious Activity Detection

#### Implementation Overview
Track failed login attempts, detect suspicious patterns, and implement progressive lockout mechanisms.

#### Required DynamoDB Table
```go
// internal/database/models/security_event.go
package models

import "time"

type SecurityEvent struct {
    EventID       string    `dynamodbav:"event_id"`        // PK: {user_id}#{timestamp}
    UserID        string    `dynamodbav:"user_id"`         // GSI
    EventType     string    `dynamodbav:"event_type"`      // GSI (login_failed, login_success, suspicious)
    IPAddress     string    `dynamodbav:"ip_address"`
    UserAgent     string    `dynamodbav:"user_agent"`
    Location      string    `dynamodbav:"location"`        // City, Country
    Timestamp     time.Time `dynamodbav:"timestamp"`
    Metadata      map[string]string `dynamodbav:"metadata"`
    RiskScore     int       `dynamodbav:"risk_score"`      // 0-100
    TTL           int64     `dynamodbav:"ttl"`             // Auto-expire after 90 days
}

type AccountLockout struct {
    UserID           string    `dynamodbav:"user_id"`           // PK
    IsLocked         bool      `dynamodbav:"is_locked"`
    FailedAttempts   int       `dynamodbav:"failed_attempts"`
    LockoutUntil     time.Time `dynamodbav:"lockout_until"`
    LastFailedLogin  time.Time `dynamodbav:"last_failed_login"`
    LockoutReason    string    `dynamodbav:"lockout_reason"`
    UnlockToken      string    `dynamodbav:"unlock_token"`      // For account recovery
    TTL              int64     `dynamodbav:"ttl"`
}
```

#### DynamoDB Table Definition (SAM Template)
```yaml
SecurityEventsTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: !Sub ${Environment}-security-events
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: event_id
        AttributeType: S
      - AttributeName: user_id
        AttributeType: S
      - AttributeName: event_type
        AttributeType: S
      - AttributeName: timestamp
        AttributeType: N
    KeySchema:
      - AttributeName: event_id
        KeyType: HASH
    GlobalSecondaryIndexes:
      - IndexName: UserIDIndex
        KeySchema:
          - AttributeName: user_id
            KeyType: HASH
          - AttributeName: timestamp
            KeyType: RANGE
        Projection:
          ProjectionType: ALL
      - IndexName: EventTypeIndex
        KeySchema:
          - AttributeName: event_type
            KeyType: HASH
          - AttributeName: timestamp
            KeyType: RANGE
        Projection:
          ProjectionType: ALL
    TimeToLiveSpecification:
      Enabled: true
      AttributeName: ttl

AccountLockoutsTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: !Sub ${Environment}-account-lockouts
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: user_id
        AttributeType: S
    KeySchema:
      - AttributeName: user_id
        KeyType: HASH
    TimeToLiveSpecification:
      Enabled: true
      AttributeName: ttl
```

#### Security Service Implementation
```go
// internal/service/security_service.go
package service

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "time"
    "yourapp/internal/database/models"
    "yourapp/internal/database/repository"
    "yourapp/internal/utils"
)

type SecurityService struct {
    eventRepo   *repository.SecurityEventRepository
    lockoutRepo *repository.AccountLockoutRepository
}

const (
    MaxFailedAttempts = 5
    InitialLockoutDuration = 15 * time.Minute
    SecondLockoutDuration = 1 * time.Hour
    PermanentLockoutThreshold = 10
)

func (s *SecurityService) RecordLoginAttempt(ctx context.Context, userID, ipAddress, userAgent string, success bool) error {
    eventType := "login_success"
    if !success {
        eventType = "login_failed"
    }

    // Calculate risk score
    riskScore := s.calculateRiskScore(ctx, userID, ipAddress, userAgent)

    event := &models.SecurityEvent{
        EventID:   fmt.Sprintf("%s#%d", userID, time.Now().UnixNano()),
        UserID:    userID,
        EventType: eventType,
        IPAddress: ipAddress,
        UserAgent: userAgent,
        Timestamp: time.Now(),
        RiskScore: riskScore,
        TTL:       time.Now().Add(90 * 24 * time.Hour).Unix(),
    }

    if err := s.eventRepo.Create(ctx, event); err != nil {
        utils.Logger.Error().Err(err).Str("user_id", userID).Msg("Failed to record security event")
        return err
    }

    // Handle lockout logic
    if !success {
        return s.handleFailedLogin(ctx, userID, riskScore)
    }

    // Reset failed attempts on successful login
    return s.lockoutRepo.ResetFailedAttempts(ctx, userID)
}

func (s *SecurityService) handleFailedLogin(ctx context.Context, userID string, riskScore int) error {
    lockout, err := s.lockoutRepo.Get(ctx, userID)
    if err != nil {
        // Create new lockout record
        lockout = &models.AccountLockout{
            UserID:         userID,
            FailedAttempts: 1,
            LastFailedLogin: time.Now(),
        }
    } else {
        lockout.FailedAttempts++
        lockout.LastFailedLogin = time.Now()
    }

    // Check if account should be locked
    if lockout.FailedAttempts >= MaxFailedAttempts {
        duration := s.calculateLockoutDuration(lockout.FailedAttempts)
        lockout.IsLocked = true
        lockout.LockoutUntil = time.Now().Add(duration)
        lockout.LockoutReason = fmt.Sprintf("Too many failed login attempts (%d)", lockout.FailedAttempts)

        // Generate unlock token for account recovery
        lockout.UnlockToken = s.generateUnlockToken()

        utils.Logger.Warn().
            Str("user_id", userID).
            Int("failed_attempts", lockout.FailedAttempts).
            Time("lockout_until", lockout.LockoutUntil).
            Msg("Account locked due to failed login attempts")
    }

    return s.lockoutRepo.Save(ctx, lockout)
}

func (s *SecurityService) calculateRiskScore(ctx context.Context, userID, ipAddress, userAgent string) int {
    score := 0

    // Check for multiple IPs in short time
    recentEvents, _ := s.eventRepo.GetRecentByUser(ctx, userID, 1*time.Hour)
    uniqueIPs := make(map[string]bool)
    for _, event := range recentEvents {
        uniqueIPs[event.IPAddress] = true
    }
    if len(uniqueIPs) > 3 {
        score += 30
    }

    // Check for unusual user agent
    if isUnusualUserAgent(userAgent) {
        score += 20
    }

    // Check for failed attempts from this IP
    ipEvents, _ := s.eventRepo.GetRecentByIP(ctx, ipAddress, 1*time.Hour)
    failedCount := 0
    for _, event := range ipEvents {
        if event.EventType == "login_failed" {
            failedCount++
        }
    }
    if failedCount > 3 {
        score += 25
    }

    // Check for known malicious IP (integrate with threat intelligence)
    if s.isKnownMaliciousIP(ctx, ipAddress) {
        score += 50
    }

    return min(score, 100)
}

func (s *SecurityService) calculateLockoutDuration(failedAttempts int) time.Duration {
    switch {
    case failedAttempts < 7:
        return InitialLockoutDuration
    case failedAttempts < PermanentLockoutThreshold:
        return SecondLockoutDuration
    default:
        return 365 * 24 * time.Hour // Effectively permanent
    }
}

func (s *SecurityService) generateUnlockToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return hex.EncodeToString(b)
}

func (s *SecurityService) IsAccountLocked(ctx context.Context, userID string) (bool, *models.AccountLockout, error) {
    lockout, err := s.lockoutRepo.Get(ctx, userID)
    if err != nil {
        return false, nil, nil
    }

    // Check if lockout has expired
    if lockout.IsLocked && time.Now().After(lockout.LockoutUntil) {
        lockout.IsLocked = false
        lockout.FailedAttempts = 0
        s.lockoutRepo.Save(ctx, lockout)
        return false, nil, nil
    }

    return lockout.IsLocked, lockout, nil
}

func isUnusualUserAgent(userAgent string) bool {
    // Implement user agent analysis
    // Check for common automation tools, scrapers, etc.
    suspicious := []string{"curl", "wget", "python", "bot", "crawler", "scraper"}
    for _, s := range suspicious {
        if contains(userAgent, s) {
            return true
        }
    }
    return false
}
```

#### Middleware Integration
```go
// internal/api/middleware/security.go
package middleware

func AccountLockoutCheck(securityService *service.SecurityService) fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Extract user identifier (email or username) from login request
        var loginReq struct {
            Email string `json:"email"`
        }

        if err := c.BodyParser(&loginReq); err != nil {
            return c.Next()
        }

        // Check if account is locked
        // Note: This requires looking up userID by email first
        isLocked, lockout, err := securityService.IsAccountLocked(c.Context(), getUserIDByEmail(loginReq.Email))
        if err != nil {
            utils.Logger.Error().Err(err).Msg("Failed to check account lockout status")
            return c.Next()
        }

        if isLocked {
            utils.Logger.Warn().
                Str("email", loginReq.Email).
                Time("lockout_until", lockout.LockoutUntil).
                Msg("Login attempt on locked account")

            return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
                "error": "Account locked",
                "message": fmt.Sprintf("Account locked until %s due to multiple failed login attempts",
                    lockout.LockoutUntil.Format(time.RFC3339)),
                "lockout_until": lockout.LockoutUntil,
                "reason": lockout.LockoutReason,
            })
        }

        return c.Next()
    }
}
```

---

### 2. TLS 1.3 Enforcement and Encryption in Transit

#### API Gateway Configuration (SAM Template)
```yaml
Resources:
  ApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub ${ServiceName}-${Environment}
      Events:
        ApiEvent:
          Type: Api
          Properties:
            Path: /{proxy+}
            Method: ANY
            RestApiId: !Ref SecureApi

  SecureApi:
    Type: AWS::Serverless::Api
    Properties:
      Name: !Sub ${ServiceName}-api-${Environment}
      StageName: !Ref Environment
      EndpointConfiguration:
        Type: REGIONAL
      Domain:
        DomainName: !Sub api.${DomainName}
        CertificateArn: !Ref ApiCertificate
        SecurityPolicy: TLS_1_2  # Note: TLS 1.3 not yet supported by API Gateway
        EndpointConfiguration: REGIONAL
      Auth:
        DefaultAuthorizer: NONE
      Cors:
        AllowMethods: "'GET,POST,PUT,DELETE,OPTIONS'"
        AllowHeaders: "'Content-Type,Authorization,X-Request-ID'"
        AllowOrigin: !Ref CorsOrigins
        AllowCredentials: true
      AccessLogSetting:
        DestinationArn: !GetAtt ApiAccessLogs.Arn
        Format: '{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","requestTime":"$context.requestTime","httpMethod":"$context.httpMethod","routeKey":"$context.routeKey","status":"$context.status","protocol":"$context.protocol","responseLength":"$context.responseLength","tlsVersion":"$context.identity.tlsVersion"}'

  ApiCertificate:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: !Sub api.${DomainName}
      ValidationMethod: DNS
      Tags:
        - Key: Environment
          Value: !Ref Environment

  ApiAccessLogs:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/apigateway/${ServiceName}-${Environment}
      RetentionInDays: 30
```

#### Security Headers Middleware
```go
// internal/api/middleware/security_headers.go
package middleware

import (
    "github.com/gofiber/fiber/v2"
)

func SecurityHeaders() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Strict Transport Security (HSTS)
        c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

        // Content Security Policy
        c.Set("Content-Security-Policy",
            "default-src 'self'; "+
            "script-src 'self'; "+
            "style-src 'self' 'unsafe-inline'; "+
            "img-src 'self' data: https:; "+
            "font-src 'self'; "+
            "connect-src 'self'; "+
            "frame-ancestors 'none'; "+
            "base-uri 'self'; "+
            "form-action 'self'")

        // Prevent clickjacking
        c.Set("X-Frame-Options", "DENY")

        // Prevent MIME sniffing
        c.Set("X-Content-Type-Options", "nosniff")

        // XSS Protection (legacy browsers)
        c.Set("X-XSS-Protection", "1; mode=block")

        // Referrer Policy
        c.Set("Referrer-Policy", "strict-origin-when-cross-origin")

        // Permissions Policy (formerly Feature Policy)
        c.Set("Permissions-Policy",
            "accelerometer=(), "+
            "camera=(), "+
            "geolocation=(), "+
            "gyroscope=(), "+
            "magnetometer=(), "+
            "microphone=(), "+
            "payment=(), "+
            "usb=()")

        // Remove server identification
        c.Set("Server", "")
        c.Set("X-Powered-By", "")

        return c.Next()
    }
}

// TLS Configuration Checker
func ValidateTLSVersion() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Note: In Lambda with API Gateway, TLS termination happens at API Gateway
        // This middleware logs the TLS version from ALB/API Gateway headers

        tlsVersion := c.Get("X-Forwarded-Proto-Version")
        if tlsVersion != "" && tlsVersion < "TLSv1.2" {
            utils.Logger.Warn().
                Str("tls_version", tlsVersion).
                Str("ip", c.IP()).
                Msg("Connection using outdated TLS version")

            return c.Status(fiber.StatusUpgradeRequired).JSON(fiber.Map{
                "error": "TLS version not supported",
                "message": "Please upgrade to TLS 1.2 or higher",
            })
        }

        return c.Next()
    }
}
```

---

### 3. API Key Management System for Service-to-Service Authentication

#### API Key Model and DynamoDB Table
```go
// internal/database/models/api_key.go
package models

import (
    "time"
)

type APIKey struct {
    KeyID        string    `dynamodbav:"key_id"`         // PK: Random UUID
    KeyHash      string    `dynamodbav:"key_hash"`       // SHA-256 hash of the key
    Name         string    `dynamodbav:"name"`           // Human-readable name
    Description  string    `dynamodbav:"description"`
    OwnerID      string    `dynamodbav:"owner_id"`       // User or service owner
    Scopes       []string  `dynamodbav:"scopes"`         // Permissions: read, write, admin
    IsActive     bool      `dynamodbav:"is_active"`
    CreatedAt    time.Time `dynamodbav:"created_at"`
    ExpiresAt    *time.Time `dynamodbav:"expires_at,omitempty"`
    LastUsedAt   *time.Time `dynamodbav:"last_used_at,omitempty"`
    UsageCount   int       `dynamodbav:"usage_count"`
    RateLimitRPM int       `dynamodbav:"rate_limit_rpm"` // Requests per minute
    AllowedIPs   []string  `dynamodbav:"allowed_ips"`    // IP whitelist
    Metadata     map[string]string `dynamodbav:"metadata"`
}
```

#### SAM Template for API Keys Table
```yaml
ApiKeysTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: !Sub ${Environment}-api-keys
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: key_id
        AttributeType: S
      - AttributeName: owner_id
        AttributeType: S
    KeySchema:
      - AttributeName: key_id
        KeyType: HASH
    GlobalSecondaryIndexes:
      - IndexName: OwnerIDIndex
        KeySchema:
          - AttributeName: owner_id
            KeyType: HASH
        Projection:
          ProjectionType: ALL
```

#### API Key Service
```go
// internal/service/api_key_service.go
package service

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "time"
    "github.com/google/uuid"
    "yourapp/internal/database/models"
    "yourapp/internal/database/repository"
)

type APIKeyService struct {
    repo *repository.APIKeyRepository
}

const (
    APIKeyPrefix = "sk_"
    APIKeyLength = 32
)

// CreateAPIKey generates a new API key
func (s *APIKeyService) CreateAPIKey(ctx context.Context, name, description, ownerID string, scopes []string, expiresIn time.Duration) (*models.APIKey, string, error) {
    // Generate cryptographically secure random key
    rawKey := make([]byte, APIKeyLength)
    if _, err := rand.Read(rawKey); err != nil {
        return nil, "", fmt.Errorf("failed to generate random key: %w", err)
    }

    // Create key string with prefix
    keyString := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(rawKey)

    // Hash the key for storage
    hash := sha256.Sum256([]byte(keyString))
    keyHash := hex.EncodeToString(hash[:])

    var expiresAt *time.Time
    if expiresIn > 0 {
        expiry := time.Now().Add(expiresIn)
        expiresAt = &expiry
    }

    apiKey := &models.APIKey{
        KeyID:        uuid.New().String(),
        KeyHash:      keyHash,
        Name:         name,
        Description:  description,
        OwnerID:      ownerID,
        Scopes:       scopes,
        IsActive:     true,
        CreatedAt:    time.Now(),
        ExpiresAt:    expiresAt,
        UsageCount:   0,
        RateLimitRPM: 1000, // Default rate limit
    }

    if err := s.repo.Create(ctx, apiKey); err != nil {
        return nil, "", fmt.Errorf("failed to store API key: %w", err)
    }

    utils.Logger.Info().
        Str("key_id", apiKey.KeyID).
        Str("owner_id", ownerID).
        Strs("scopes", scopes).
        Msg("API key created")

    // Return the plain text key ONLY once during creation
    return apiKey, keyString, nil
}

// ValidateAPIKey checks if an API key is valid
func (s *APIKeyService) ValidateAPIKey(ctx context.Context, keyString string, requiredScope string) (*models.APIKey, error) {
    // Hash the provided key
    hash := sha256.Sum256([]byte(keyString))
    keyHash := hex.EncodeToString(hash[:])

    // Lookup by hash
    apiKey, err := s.repo.GetByHash(ctx, keyHash)
    if err != nil {
        return nil, fmt.Errorf("invalid API key")
    }

    // Check if key is active
    if !apiKey.IsActive {
        return nil, fmt.Errorf("API key is inactive")
    }

    // Check expiration
    if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
        return nil, fmt.Errorf("API key has expired")
    }

    // Check scopes
    if requiredScope != "" && !contains(apiKey.Scopes, requiredScope) {
        return nil, fmt.Errorf("API key lacks required scope: %s", requiredScope)
    }

    // Update last used timestamp and usage count
    go s.updateUsageStats(context.Background(), apiKey.KeyID)

    return apiKey, nil
}

func (s *APIKeyService) updateUsageStats(ctx context.Context, keyID string) {
    now := time.Now()
    s.repo.UpdateUsage(ctx, keyID, &now)
}
```

#### API Key Authentication Middleware
```go
// internal/api/middleware/api_key_auth.go
package middleware

import (
    "strings"
    "github.com/gofiber/fiber/v2"
    "yourapp/internal/service"
)

func APIKeyAuth(apiKeyService *service.APIKeyService, requiredScope string) fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Extract API key from header
        authHeader := c.Get("Authorization")
        if authHeader == "" {
            authHeader = c.Get("X-API-Key")
        }

        if authHeader == "" {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Missing API key",
                "message": "Provide API key in Authorization or X-API-Key header",
            })
        }

        // Remove "Bearer " prefix if present
        apiKey := strings.TrimPrefix(authHeader, "Bearer ")

        // Validate API key
        keyData, err := apiKeyService.ValidateAPIKey(c.Context(), apiKey, requiredScope)
        if err != nil {
            utils.Logger.Warn().
                Err(err).
                Str("ip", c.IP()).
                Msg("Invalid API key used")

            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "Invalid API key",
                "message": err.Error(),
            })
        }

        // Store API key metadata in context
        c.Locals("api_key", keyData)
        c.Locals("api_key_owner", keyData.OwnerID)
        c.Locals("api_key_scopes", keyData.Scopes)

        utils.Logger.Debug().
            Str("key_id", keyData.KeyID).
            Str("owner_id", keyData.OwnerID).
            Strs("scopes", keyData.Scopes).
            Msg("API key authenticated")

        return c.Next()
    }
}
```

#### Route Configuration with API Key Auth
```go
// internal/api/routes/routes.go

// API endpoints for API key management (admin only)
apiKeyRoutes := protected.Group("/api-keys", middleware.RequirePermission("admin"))
apiKeyRoutes.Post("/", handlers.CreateAPIKey)           // Create new API key
apiKeyRoutes.Get("/", handlers.ListAPIKeys)             // List all keys
apiKeyRoutes.Get("/:id", handlers.GetAPIKey)            // Get specific key details
apiKeyRoutes.Put("/:id", handlers.UpdateAPIKey)         // Update key (scopes, rate limits)
apiKeyRoutes.Delete("/:id", handlers.RevokeAPIKey)      // Revoke/delete key
apiKeyRoutes.Post("/:id/rotate", handlers.RotateAPIKey) // Rotate key

// Service-to-service routes using API key auth
serviceRoutes := app.Group("/api/v1/service", middleware.APIKeyAuth(apiKeyService, "service"))
serviceRoutes.Get("/data", handlers.GetServiceData)
serviceRoutes.Post("/webhook", handlers.HandleWebhook)
```

---

### 4. Comprehensive Input Validation and Sanitization Framework

#### Validation Package Setup
```go
// internal/utils/validation.go
package utils

import (
    "fmt"
    "regexp"
    "strings"
    "github.com/go-playground/validator/v10"
    "github.com/microcosm-cc/bluemonday"
)

var (
    validate *validator.Validate
    sanitizer *bluemonday.Policy
)

func InitValidator() {
    validate = validator.New()

    // Register custom validators
    validate.RegisterValidation("username", validateUsername)
    validate.RegisterValidation("strong_password", validateStrongPassword)
    validate.RegisterValidation("no_sql_injection", validateNoSQLInjection)
    validate.RegisterValidation("safe_string", validateSafeString)

    // Initialize HTML sanitizer (strict policy)
    sanitizer = bluemonday.StrictPolicy()
}

// Custom validator for usernames
func validateUsername(fl validator.FieldLevel) bool {
    username := fl.Field().String()
    // Allow alphanumeric, underscore, hyphen, 3-32 characters
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]{3,32}$`, username)
    return matched
}

// Validate strong password
func validateStrongPassword(fl validator.FieldLevel) bool {
    password := fl.Field().String()

    // Check length
    if len(password) < 12 {
        return false
    }

    // Check for uppercase
    hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
    // Check for lowercase
    hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
    // Check for digit
    hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
    // Check for special character
    hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)

    return hasUpper && hasLower && hasDigit && hasSpecial
}

// Check for common SQL injection patterns
func validateNoSQLInjection(fl validator.FieldLevel) bool {
    value := fl.Field().String()

    // Common SQL injection patterns
    patterns := []string{
        `(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)[\s\(]`,
        `(?i)(and|or)[\s]+[\d\w]+[\s]*=`,
        `--|#|\/\*|\*\/`,
        `(?i)(xp_|sp_)`,
    }

    for _, pattern := range patterns {
        matched, _ := regexp.MatchString(pattern, value)
        if matched {
            return false
        }
    }

    return true
}

// Validate safe string (no special characters that could cause XSS)
func validateSafeString(fl validator.FieldLevel) bool {
    value := fl.Field().String()

    // Check for potentially dangerous characters
    dangerous := []string{"<", ">", "\"", "'", "&", "`", "\\"}
    for _, char := range dangerous {
        if strings.Contains(value, char) {
            return false
        }
    }

    return true
}

// SanitizeHTML removes all HTML tags and returns plain text
func SanitizeHTML(input string) string {
    return sanitizer.Sanitize(input)
}

// SanitizeString removes potentially dangerous characters
func SanitizeString(input string) string {
    // Remove null bytes
    input = strings.ReplaceAll(input, "\x00", "")

    // Trim whitespace
    input = strings.TrimSpace(input)

    // Remove control characters
    input = regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(input, "")

    return input
}

// ValidateStruct validates a struct using validator tags
func ValidateStruct(s interface{}) error {
    if err := validate.Struct(s); err != nil {
        if validationErrors, ok := err.(validator.ValidationErrors); ok {
            return formatValidationErrors(validationErrors)
        }
        return err
    }
    return nil
}

func formatValidationErrors(errs validator.ValidationErrors) error {
    var messages []string
    for _, err := range errs {
        switch err.Tag() {
        case "required":
            messages = append(messages, fmt.Sprintf("%s is required", err.Field()))
        case "email":
            messages = append(messages, fmt.Sprintf("%s must be a valid email", err.Field()))
        case "min":
            messages = append(messages, fmt.Sprintf("%s must be at least %s characters", err.Field(), err.Param()))
        case "max":
            messages = append(messages, fmt.Sprintf("%s must be at most %s characters", err.Field(), err.Param()))
        case "username":
            messages = append(messages, fmt.Sprintf("%s must be 3-32 alphanumeric characters", err.Field()))
        case "strong_password":
            messages = append(messages, fmt.Sprintf("%s must be at least 12 characters with uppercase, lowercase, number, and special character", err.Field()))
        default:
            messages = append(messages, fmt.Sprintf("%s failed validation: %s", err.Field(), err.Tag()))
        }
    }
    return fmt.Errorf("validation failed: %s", strings.Join(messages, "; "))
}
```

#### Request Validation Models
```go
// internal/api/handlers/validation_models.go
package handlers

type RegisterRequest struct {
    Email    string `json:"email" validate:"required,email,max=255"`
    Username string `json:"username" validate:"required,username,no_sql_injection"`
    Password string `json:"password" validate:"required,strong_password"`
    Name     string `json:"name" validate:"required,min=2,max=100,safe_string"`
}

type LoginRequest struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=1"`
}

type UpdateProfileRequest struct {
    Name        string `json:"name" validate:"omitempty,min=2,max=100,safe_string"`
    Bio         string `json:"bio" validate:"omitempty,max=500,safe_string"`
    Website     string `json:"website" validate:"omitempty,url,max=255"`
    PhoneNumber string `json:"phone_number" validate:"omitempty,e164"` // E.164 format
}

type CreateAPIKeyRequest struct {
    Name        string   `json:"name" validate:"required,min=3,max=100,safe_string"`
    Description string   `json:"description" validate:"omitempty,max=500,safe_string"`
    Scopes      []string `json:"scopes" validate:"required,min=1,dive,oneof=read write admin service"`
    ExpiresIn   int      `json:"expires_in" validate:"omitempty,min=1,max=31536000"` // Max 1 year in seconds
}
```

#### Validation Middleware
```go
// internal/api/middleware/validation.go
package middleware

import (
    "github.com/gofiber/fiber/v2"
    "yourapp/internal/utils"
)

// ValidateRequest validates and sanitizes incoming requests
func ValidateRequest() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Get content type
        contentType := c.Get("Content-Type")

        // Only validate JSON requests
        if !strings.Contains(contentType, "application/json") {
            return c.Next()
        }

        // Log raw body for audit (be careful with sensitive data)
        bodyBytes := c.Body()
        utils.Logger.Debug().
            Str("path", c.Path()).
            Str("method", c.Method()).
            Int("body_size", len(bodyBytes)).
            Msg("Request received")

        // Check for excessively large payloads
        if len(bodyBytes) > 1024*1024 { // 1MB limit
            return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
                "error": "Request body too large",
                "message": "Maximum request size is 1MB",
            })
        }

        return c.Next()
    }
}

// SanitizeOutput sanitizes response data to prevent XSS
func SanitizeOutput() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Process request
        err := c.Next()

        // Add security headers to response
        c.Set("X-Content-Type-Options", "nosniff")

        return err
    }
}
```

#### Handler with Validation
```go
// internal/api/handlers/auth.go
func Register(c *fiber.Ctx) error {
    var req RegisterRequest

    // Parse request body
    if err := c.BodyParser(&req); err != nil {
        utils.Logger.Warn().Err(err).Msg("Failed to parse registration request")
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request format",
        })
    }

    // Validate request
    if err := utils.ValidateStruct(&req); err != nil {
        utils.Logger.Debug().Err(err).Msg("Registration validation failed")
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Validation failed",
            "message": err.Error(),
        })
    }

    // Sanitize inputs
    req.Email = strings.ToLower(strings.TrimSpace(req.Email))
    req.Username = utils.SanitizeString(req.Username)
    req.Name = utils.SanitizeHTML(req.Name)

    // Check password against HaveIBeenPwned (see section 9)
    if isCompromised, _ := checkPasswordBreach(req.Password); isCompromised {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Password compromised",
            "message": "This password has been found in data breaches. Please choose a different password.",
        })
    }

    // Proceed with user creation...
    user, err := userService.CreateUser(c.Context(), &req)
    if err != nil {
        return handleError(c, err)
    }

    utils.Logger.Info().
        Str("user_id", user.UserID).
        Str("email", user.Email).
        Msg("User registered successfully")

    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "User created successfully",
        "user_id": user.UserID,
    })
}
```

---

### 5. Audit Logging for Sensitive Operations

#### Audit Log Model
```go
// internal/database/models/audit_log.go
package models

import (
    "time"
)

type AuditLog struct {
    LogID        string    `dynamodbav:"log_id"`        // PK: UUID
    Timestamp    time.Time `dynamodbav:"timestamp"`     // GSI Range Key
    UserID       string    `dynamodbav:"user_id"`       // GSI Partition Key
    Action       string    `dynamodbav:"action"`        // GSI Partition Key
    Resource     string    `dynamodbav:"resource"`      // e.g., "user", "api_key", "session"
    ResourceID   string    `dynamodbav:"resource_id"`   // ID of affected resource
    Details      string    `dynamodbav:"details"`       // JSON string with details
    IPAddress    string    `dynamodbav:"ip_address"`
    UserAgent    string    `dynamodbav:"user_agent"`
    RequestID    string    `dynamodbav:"request_id"`
    Status       string    `dynamodbav:"status"`        // success, failure, error
    ErrorMessage string    `dynamodbav:"error_message,omitempty"`
    Changes      map[string]interface{} `dynamodbav:"changes,omitempty"` // Before/after values
    TTL          int64     `dynamodbav:"ttl"`           // Retention period
}

const (
    // Audit Actions
    ActionUserCreated        = "user.created"
    ActionUserUpdated        = "user.updated"
    ActionUserDeleted        = "user.deleted"
    ActionUserLogin          = "user.login"
    ActionUserLogout         = "user.logout"
    ActionPasswordChanged    = "user.password_changed"
    ActionPermissionGranted  = "permission.granted"
    ActionPermissionRevoked  = "permission.revoked"
    ActionAPIKeyCreated      = "apikey.created"
    ActionAPIKeyRevoked      = "apikey.revoked"
    ActionDataExported       = "data.exported"
    ActionDataDeleted        = "data.deleted"
    ActionConfigChanged      = "config.changed"
)
```

#### SAM Template for Audit Logs
```yaml
AuditLogsTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: !Sub ${Environment}-audit-logs
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: log_id
        AttributeType: S
      - AttributeName: user_id
        AttributeType: S
      - AttributeName: action
        AttributeType: S
      - AttributeName: timestamp
        AttributeType: N
    KeySchema:
      - AttributeName: log_id
        KeyType: HASH
    GlobalSecondaryIndexes:
      - IndexName: UserIDIndex
        KeySchema:
          - AttributeName: user_id
            KeyType: HASH
          - AttributeName: timestamp
            KeyType: RANGE
        Projection:
          ProjectionType: ALL
      - IndexName: ActionIndex
        KeySchema:
          - AttributeName: action
            KeyType: HASH
          - AttributeName: timestamp
            KeyType: RANGE
        Projection:
          ProjectionType: ALL
    TimeToLiveSpecification:
      Enabled: true
      AttributeName: ttl
    StreamSpecification:
      StreamViewType: NEW_AND_OLD_IMAGES
    PointInTimeRecoverySpecification:
      PointInTimeRecoveryEnabled: true
```

#### Audit Logger Service
```go
// internal/service/audit_service.go
package service

import (
    "context"
    "encoding/json"
    "time"
    "github.com/google/uuid"
    "yourapp/internal/database/models"
    "yourapp/internal/database/repository"
    "yourapp/internal/utils"
)

type AuditService struct {
    repo *repository.AuditLogRepository
}

// LogAudit creates an audit log entry
func (s *AuditService) LogAudit(ctx context.Context, entry *models.AuditLog) error {
    entry.LogID = uuid.New().String()
    entry.Timestamp = time.Now()

    // Set TTL based on data retention policy
    // Keep audit logs for 7 years (compliance requirement)
    entry.TTL = time.Now().Add(7 * 365 * 24 * time.Hour).Unix()

    if err := s.repo.Create(ctx, entry); err != nil {
        utils.Logger.Error().
            Err(err).
            Str("action", entry.Action).
            Str("user_id", entry.UserID).
            Msg("Failed to create audit log")
        return err
    }

    // Also log to CloudWatch for real-time monitoring
    utils.Logger.Info().
        Str("audit_log_id", entry.LogID).
        Str("action", entry.Action).
        Str("user_id", entry.UserID).
        Str("resource", entry.Resource).
        Str("resource_id", entry.ResourceID).
        Str("status", entry.Status).
        Msg("Audit log created")

    return nil
}

// Helper function to log user actions
func (s *AuditService) LogUserAction(ctx context.Context, userID, action, resource, resourceID string, details interface{}, ipAddress, userAgent, requestID string) error {
    detailsJSON, _ := json.Marshal(details)

    return s.LogAudit(ctx, &models.AuditLog{
        UserID:     userID,
        Action:     action,
        Resource:   resource,
        ResourceID: resourceID,
        Details:    string(detailsJSON),
        IPAddress:  ipAddress,
        UserAgent:  userAgent,
        RequestID:  requestID,
        Status:     "success",
    })
}

// Helper to log changes (before/after)
func (s *AuditService) LogChange(ctx context.Context, userID, action, resource, resourceID string, before, after interface{}, ipAddress, userAgent, requestID string) error {
    changes := map[string]interface{}{
        "before": before,
        "after":  after,
    }

    return s.LogAudit(ctx, &models.AuditLog{
        UserID:     userID,
        Action:     action,
        Resource:   resource,
        ResourceID: resourceID,
        Changes:    changes,
        IPAddress:  ipAddress,
        UserAgent:  userAgent,
        RequestID:  requestID,
        Status:     "success",
    })
}
```

#### Audit Logging Middleware
```go
// internal/api/middleware/audit.go
package middleware

import (
    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
    "yourapp/internal/service"
)

func AuditLogging(auditService *service.AuditService) fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Generate request ID if not present
        requestID := c.Get("X-Request-ID")
        if requestID == "" {
            requestID = uuid.New().String()
            c.Set("X-Request-ID", requestID)
        }

        // Store request ID in context
        c.Locals("request_id", requestID)

        // Get user info if authenticated
        userID := ""
        if user := c.Locals("user"); user != nil {
            if u, ok := user.(*models.User); ok {
                userID = u.UserID
            }
        }

        // Store audit context
        c.Locals("audit_context", &AuditContext{
            UserID:    userID,
            IPAddress: c.IP(),
            UserAgent: c.Get("User-Agent"),
            RequestID: requestID,
        })

        return c.Next()
    }
}

type AuditContext struct {
    UserID    string
    IPAddress string
    UserAgent string
    RequestID string
}

// GetAuditContext retrieves audit context from fiber context
func GetAuditContext(c *fiber.Ctx) *AuditContext {
    if ctx := c.Locals("audit_context"); ctx != nil {
        if auditCtx, ok := ctx.(*AuditContext); ok {
            return auditCtx
        }
    }
    return &AuditContext{}
}
```

#### Usage in Handlers
```go
// internal/api/handlers/user.go

func UpdateProfile(c *fiber.Ctx) error {
    user := c.Locals("user").(*models.User)
    auditCtx := middleware.GetAuditContext(c)

    var req UpdateProfileRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
    }

    // Get current state for audit log
    beforeState := map[string]interface{}{
        "name": user.Name,
        "bio":  user.Metadata["bio"],
    }

    // Update user
    user.Name = req.Name
    if req.Bio != "" {
        user.Metadata["bio"] = req.Bio
    }

    if err := userService.UpdateUser(c.Context(), user); err != nil {
        // Log failure
        auditService.LogAudit(c.Context(), &models.AuditLog{
            UserID:       user.UserID,
            Action:       models.ActionUserUpdated,
            Resource:     "user",
            ResourceID:   user.UserID,
            IPAddress:    auditCtx.IPAddress,
            UserAgent:    auditCtx.UserAgent,
            RequestID:    auditCtx.RequestID,
            Status:       "failure",
            ErrorMessage: err.Error(),
        })
        return handleError(c, err)
    }

    // Get new state
    afterState := map[string]interface{}{
        "name": user.Name,
        "bio":  user.Metadata["bio"],
    }

    // Log successful change
    auditService.LogChange(
        c.Context(),
        user.UserID,
        models.ActionUserUpdated,
        "user",
        user.UserID,
        beforeState,
        afterState,
        auditCtx.IPAddress,
        auditCtx.UserAgent,
        auditCtx.RequestID,
    )

    return c.JSON(fiber.Map{
        "message": "Profile updated",
        "user":    user,
    })
}
```

---

### 6. Least-Privilege IAM Roles

#### Enhanced SAM Template with Least-Privilege IAM
```yaml
Resources:
  ApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub ${ServiceName}-${Environment}
      # ... other properties ...
      Policies:
        # Specific DynamoDB permissions per table
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
        - DynamoDBCrudPolicy:
            TableName: !Ref SessionsTable
        - DynamoDBCrudPolicy:
            TableName: !Ref APIKeysTable
        - DynamoDBCrudPolicy:
            TableName: !Ref AuditLogsTable
        - DynamoDBCrudPolicy:
            TableName: !Ref SecurityEventsTable
        - DynamoDBCrudPolicy:
            TableName: !Ref AccountLockoutsTable

        # CloudWatch Logs (specific log group)
        - Statement:
            - Effect: Allow
              Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
              Resource: !Sub arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/${ServiceName}-${Environment}:*

        # KMS for encryption (if using AWS KMS)
        - Statement:
            - Effect: Allow
              Action:
                - kms:Decrypt
                - kms:GenerateDataKey
              Resource: !GetAtt EncryptionKey.Arn
              Condition:
                StringEquals:
                  kms:ViaService: !Sub dynamodb.${AWS::Region}.amazonaws.com

        # Secrets Manager (for sensitive config)
        - Statement:
            - Effect: Allow
              Action:
                - secretsmanager:GetSecretValue
              Resource:
                - !Ref JWTSecretArn
                - !Ref EncryptionKeySecretArn

        # X-Ray (for tracing)
        - Statement:
            - Effect: Allow
              Action:
                - xray:PutTraceSegments
                - xray:PutTelemetryRecords
              Resource: "*"

  # KMS Key for encryption
  EncryptionKey:
    Type: AWS::KMS::Key
    Properties:
      Description: !Sub Encryption key for ${ServiceName}-${Environment}
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Sub arn:aws:iam::${AWS::AccountId}:root
            Action: kms:*
            Resource: '*'
          - Sid: Allow Lambda to use the key
            Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action:
              - kms:Decrypt
              - kms:GenerateDataKey
            Resource: '*'
            Condition:
              StringEquals:
                kms:ViaService: !Sub dynamodb.${AWS::Region}.amazonaws.com
          - Sid: Allow DynamoDB to use the key
            Effect: Allow
            Principal:
              Service: dynamodb.amazonaws.com
            Action:
              - kms:Decrypt
              - kms:GenerateDataKey
              - kms:CreateGrant
            Resource: '*'

  EncryptionKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Sub alias/${ServiceName}-${Environment}
      TargetKeyId: !Ref EncryptionKey

  # IAM Role for GitHub Actions deployment (separate from runtime)
  GitHubActionsDeploymentRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub ${ServiceName}-${Environment}-github-actions
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: !Sub arn:aws:iam::${AWS::AccountId}:oidc-provider/token.actions.githubusercontent.com
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                token.actions.githubusercontent.com:aud: sts.amazonaws.com
              StringLike:
                token.actions.githubusercontent.com:sub: !Sub repo:${GitHubOrg}/${GitHubRepo}:*
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AWSCloudFormationFullAccess
      Policies:
        - PolicyName: SAMDeploymentPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:PutObject
                  - s3:GetObject
                Resource: !Sub arn:aws:s3:::${SAMBucket}/*
              - Effect: Allow
                Action:
                  - lambda:UpdateFunctionCode
                  - lambda:UpdateFunctionConfiguration
                  - lambda:GetFunction
                  - lambda:PublishVersion
                Resource: !Sub arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:${ServiceName}-${Environment}
              - Effect: Allow
                Action:
                  - iam:PassRole
                Resource: !GetAtt ApiFunctionRole.Arn
```

---

### 7. Automated Security Scanning in CI/CD Pipeline

#### Enhanced GitHub Actions Workflow
```yaml
# .github/workflows/security-scan.yml
name: Security Scanning

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Run security scan daily at 2 AM UTC
    - cron: '0 2 * * *'

env:
  GO_VERSION: '1.21'

jobs:
  gosec:
    name: GoSec Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Gosec Security Scanner
        uses: securego/gosec@master
        with:
          args: '-fmt sarif -out gosec-results.sarif ./...'

      - name: Upload GoSec results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: gosec-results.sarif

  snyk:
    name: Snyk Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: ${{ env.GO_VERSION }}

      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/golang@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high --sarif-file-output=snyk-results.sarif

      - name: Upload Snyk results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: snyk-results.sarif

  trivy:
    name: Trivy Vulnerability Scanner
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: trivy-results.sarif

  codeql:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v3

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: go

      - name: Autobuild
        uses: github/codeql-action/autobuild@v2

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2

  dependency-check:
    name: OWASP Dependency Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run OWASP Dependency-Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'gofiber-app'
          path: '.'
          format: 'HTML'
          out: 'dependency-check-report'

      - name: Upload Dependency-Check Report
        uses: actions/upload-artifact@v3
        with:
          name: dependency-check-report
          path: dependency-check-report

  security-gate:
    name: Security Gate
    runs-on: ubuntu-latest
    needs: [gosec, snyk, trivy, codeql]
    if: github.event_name == 'pull_request'
    steps:
      - name: Check Security Scan Results
        run: |
          echo "All security scans completed successfully"
          echo "✅ GoSec: PASSED"
          echo "✅ Snyk: PASSED"
          echo "✅ Trivy: PASSED"
          echo "✅ CodeQL: PASSED"
```

#### Integration with Deploy Workflow
```yaml
# .github/workflows/deploy.yml (enhanced)
jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run security scans
        run: |
          # Run gosec
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec -fmt json -out gosec-report.json ./...

          # Check for critical/high severity issues
          CRITICAL_COUNT=$(cat gosec-report.json | jq '[.Issues[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length')

          if [ $CRITICAL_COUNT -gt 0 ]; then
            echo "❌ Found $CRITICAL_COUNT critical/high severity security issues"
            cat gosec-report.json | jq '.Issues[] | select(.severity == "HIGH" or .severity == "CRITICAL")'
            exit 1
          fi

          echo "✅ No critical security issues found"

  deploy:
    needs: [test, build, security-scan]
    runs-on: ubuntu-latest
    # ... rest of deployment job
```

---

### 8. Secrets Scanning and Pre-commit Hooks

#### Pre-commit Hook Configuration
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: check-merge-conflict
      - id: detect-private-key

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/golangci/golangci-lint
    rev: v1.55.2
    hooks:
      - id: golangci-lint

  - repo: https://github.com/securego/gosec
    rev: v2.18.2
    hooks:
      - id: gosec
        args: [-exclude=G104]
```

#### GitLeaks Configuration
```toml
# .gitleaks.toml
title = "Gitleaks Configuration"

[extend]
useDefault = true

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''

[[rules]]
id = "aws-secret-key"
description = "AWS Secret Key"
regex = '''(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]'''

[[rules]]
id = "jwt-secret"
description = "JWT Secret"
regex = '''(?i)jwt(.{0,20})?['"][0-9a-zA-Z\/+]{32,}['"]'''

[[rules]]
id = "generic-api-key"
description = "Generic API Key"
regex = '''(?i)(api[_-]?key|apikey)(.{0,20})?['"][0-9a-zA-Z]{32,}['"]'''

[allowlist]
description = "Allowlist"
paths = [
  '''\.env\.example$''',
  '''README\.md$''',
  '''\.pre-commit-config\.yaml$'''
]
```

#### Setup Script
```bash
# scripts/setup-hooks.sh
#!/bin/bash

echo "Setting up security pre-commit hooks..."

# Install pre-commit
pip install pre-commit

# Install gitleaks
if ! command -v gitleaks &> /dev/null; then
    echo "Installing gitleaks..."
    brew install gitleaks || \
    go install github.com/gitleaks/gitleaks/v8@latest
fi

# Install detect-secrets
pip install detect-secrets

# Create baseline for detect-secrets
detect-secrets scan > .secrets.baseline

# Install pre-commit hooks
pre-commit install
pre-commit install --hook-type commit-msg

# Run initial scan
echo "Running initial security scan..."
pre-commit run --all-files

echo "✅ Security hooks installed successfully!"
echo ""
echo "To test: git commit -m 'test'"
echo "To bypass (NOT recommended): git commit --no-verify"
```

#### GitHub Actions Secret Scanning
```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  gitleaks:
    name: GitLeaks Secret Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Run GitLeaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

  truffleho:
    name: TruffleHog Secret Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Run TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

---

### 9. Password Security Enhancements

#### Password Breach Checking
```go
// internal/service/password_service.go
package service

import (
    "context"
    "crypto/sha1"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"
)

type PasswordService struct {
    client *http.Client
}

func NewPasswordService() *PasswordService {
    return &PasswordService{
        client: &http.Client{
            Timeout: 5 * time.Second,
        },
    }
}

// CheckPasswordBreach checks if password has been in a data breach using HaveIBeenPwned API
func (s *PasswordService) CheckPasswordBreach(ctx context.Context, password string) (bool, int, error) {
    // Hash password with SHA-1 (required by HIBP API)
    hash := sha1.Sum([]byte(password))
    hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))

    // Use k-anonymity: send only first 5 chars of hash
    prefix := hashStr[:5]
    suffix := hashStr[5:]

    // Query HIBP API
    url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return false, 0, err
    }

    req.Header.Set("User-Agent", "GoFiber-Lambda-App")
    req.Header.Set("Add-Padding", "true") // Adds random padding for privacy

    resp, err := s.client.Do(req)
    if err != nil {
        utils.Logger.Warn().Err(err).Msg("Failed to check password breach")
        // Fail open - don't block user if HIBP is down
        return false, 0, nil
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return false, 0, fmt.Errorf("HIBP API returned status %d", resp.StatusCode)
    }

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return false, 0, err
    }

    // Check if our hash suffix is in the response
    lines := strings.Split(string(body), "\n")
    for _, line := range lines {
        parts := strings.Split(strings.TrimSpace(line), ":")
        if len(parts) != 2 {
            continue
        }

        if parts[0] == suffix {
            // Password found in breach
            var count int
            fmt.Sscanf(parts[1], "%d", &count)

            utils.Logger.Warn().
                Int("breach_count", count).
                Msg("Password found in breach database")

            return true, count, nil
        }
    }

    return false, 0, nil
}

// CalculatePasswordStrength using zxcvbn algorithm
func (s *PasswordService) CalculatePasswordStrength(password string, userInputs []string) *PasswordStrength {
    // Use github.com/nbutton23/zxcvbn-go
    result := zxcvbn.PasswordStrength(password, userInputs)

    return &PasswordStrength{
        Score:       result.Score,       // 0-4
        Entropy:     result.Entropy,
        CrackTime:   result.CrackTimeDisplay,
        Warning:     result.Feedback.Warning,
        Suggestions: result.Feedback.Suggestions,
    }
}

type PasswordStrength struct {
    Score       int      // 0 (weak) to 4 (strong)
    Entropy     float64
    CrackTime   string
    Warning     string
    Suggestions []string
}
```

#### Enhanced Registration Handler
```go
// internal/api/handlers/auth.go (enhanced)

func Register(c *fiber.Ctx) error {
    var req RegisterRequest

    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request format",
        })
    }

    // Validate request
    if err := utils.ValidateStruct(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Validation failed",
            "message": err.Error(),
        })
    }

    // Check password breach
    isBreached, breachCount, err := passwordService.CheckPasswordBreach(c.Context(), req.Password)
    if err != nil {
        utils.Logger.Warn().Err(err).Msg("Password breach check failed")
    }

    if isBreached {
        utils.Logger.Warn().
            Int("breach_count", breachCount).
            Str("email", req.Email).
            Msg("User attempted to use breached password")

        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Password compromised",
            "message": fmt.Sprintf("This password has appeared in %d data breaches. Please choose a different password.", breachCount),
            "breach_count": breachCount,
        })
    }

    // Calculate password strength
    strength := passwordService.CalculatePasswordStrength(req.Password, []string{
        req.Email,
        req.Username,
        req.Name,
    })

    if strength.Score < 3 {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Password too weak",
            "message": "Please choose a stronger password",
            "strength": strength.Score,
            "warning": strength.Warning,
            "suggestions": strength.Suggestions,
        })
    }

    // Store password strength score with user for metrics
    user, err := userService.CreateUser(c.Context(), &req)
    if err != nil {
        return handleError(c, err)
    }

    // Audit log
    auditService.LogUserAction(
        c.Context(),
        user.UserID,
        models.ActionUserCreated,
        "user",
        user.UserID,
        map[string]interface{}{
            "password_strength": strength.Score,
        },
        c.IP(),
        c.Get("User-Agent"),
        c.Locals("request_id").(string),
    )

    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "User created successfully",
        "user_id": user.UserID,
    })
}
```

#### Password Strength API Endpoint
```go
// POST /api/v1/auth/check-password
func CheckPasswordStrength(c *fiber.Ctx) error {
    var req struct {
        Password   string   `json:"password" validate:"required"`
        UserInputs []string `json:"user_inputs"` // Optional context (email, username, etc.)
    }

    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request",
        })
    }

    // Check breach
    isBreached, breachCount, _ := passwordService.CheckPasswordBreach(c.Context(), req.Password)

    // Calculate strength
    strength := passwordService.CalculatePasswordStrength(req.Password, req.UserInputs)

    return c.JSON(fiber.Map{
        "is_breached":   isBreached,
        "breach_count":  breachCount,
        "strength_score": strength.Score,
        "crack_time":    strength.CrackTime,
        "warning":       strength.Warning,
        "suggestions":   strength.Suggestions,
        "passes_policy": strength.Score >= 3 && !isBreached,
    })
}
```

---

## Implementation Priority

Based on security impact and implementation complexity:

### Phase 1 - Critical (Implement First)
1. **Comprehensive Input Validation** - Prevents injection attacks
2. **TLS 1.3 Enforcement** - Protects data in transit
3. **Audit Logging** - Required for compliance and incident response

### Phase 2 - High Priority
4. **Account Lockout and Suspicious Activity** - Prevents brute force attacks
5. **Password Security Enhancements** - Improves overall security posture
6. **Least-Privilege IAM Roles** - Reduces blast radius

### Phase 3 - Important
7. **API Key Management** - Enables secure service integration
8. **Secrets Scanning** - Prevents credential leaks
9. **Automated Security Scanning** - Continuous security validation

---

## Testing and Validation

### Unit Tests
```go
// internal/service/security_service_test.go
func TestAccountLockout(t *testing.T) {
    // Test lockout after max failed attempts
    // Test lockout duration calculation
    // Test risk score calculation
}

// internal/service/api_key_service_test.go
func TestAPIKeyValidation(t *testing.T) {
    // Test key generation
    // Test key validation
    // Test scope checking
    // Test expiration
}

// internal/service/password_service_test.go
func TestPasswordBreach(t *testing.T) {
    // Test known breached password
    // Test safe password
    // Test API failure handling
}
```

### Integration Tests
```go
// tests/integration/security_test.go
func TestAccountLockoutFlow(t *testing.T) {
    // Simulate multiple failed login attempts
    // Verify account locked response
    // Verify lockout expiration
}

func TestAPIKeyAuthFlow(t *testing.T) {
    // Create API key
    // Use API key for authentication
    // Test invalid API key rejection
    // Test scope enforcement
}
```

---

## Monitoring and Alerting

### CloudWatch Alarms
```yaml
# deployments/monitoring.yaml
Resources:
  HighFailedLoginAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub ${ServiceName}-${Environment}-high-failed-logins
      MetricName: FailedLoginAttempts
      Namespace: !Sub ${ServiceName}
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      AlarmActions:
        - !Ref SecurityAlertsTopicArn

  AccountLockoutAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub ${ServiceName}-${Environment}-account-lockouts
      MetricName: AccountLockouts
      Namespace: !Sub ${ServiceName}
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      AlarmActions:
        - !Ref SecurityAlertsTopicArn

  HighRiskScoreAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub ${ServiceName}-${Environment}-high-risk-events
      MetricName: HighRiskSecurityEvents
      Namespace: !Sub ${ServiceName}
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      AlarmActions:
        - !Ref SecurityAlertsTopicArn
```

---

## Documentation

### Security README
Create `SECURITY.md` in repository root:
- Vulnerability reporting process
- Security features overview
- Security best practices
- Incident response procedures

### API Documentation
Document all security-related endpoints:
- Authentication flows
- API key management
- Password policies
- Rate limiting

---

## Compliance Checklist

- [ ] All sensitive data encrypted in transit (TLS 1.3)
- [ ] All sensitive data encrypted at rest (KMS)
- [ ] Audit logs for all sensitive operations
- [ ] Password breach checking implemented
- [ ] Account lockout mechanism in place
- [ ] MFA capability available
- [ ] API key management system
- [ ] Input validation on all endpoints
- [ ] Security headers on all responses
- [ ] Automated security scanning in CI/CD
- [ ] Secret scanning enabled
- [ ] Least-privilege IAM roles
- [ ] Regular security training for team
- [ ] Incident response plan documented
- [ ] Security monitoring and alerting configured

---

## Next Steps

1. Review and approve this security implementation guide
2. Create GitHub issues for each enhancement
3. Assign priorities and team members
4. Begin Phase 1 implementation
5. Update PROJECT_STANDARDS.md with implemented features
6. Schedule security review after each phase
7. Plan penetration testing after full implementation

---

**Document Version:** 1.0
**Last Updated:** November 19, 2025
**Maintainer:** DevSecOps Team
