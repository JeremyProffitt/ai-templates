# Coding Standards - Go/Fiber Patterns v1.0

**Organization:** Ally Financial SRE/DevSecOps
**Last Updated:** November 19, 2025

## Overview

This document defines coding standards and patterns for Go applications using the Fiber framework on AWS Lambda.

---

## Go/Fiber Specific Patterns

### Route Organization

```go
// internal/api/routes/routes.go
package routes

import (
    "github.com/gofiber/fiber/v2"
    "yourapp/internal/api/handlers"
    "yourapp/internal/api/middleware"
)

func Setup(app *fiber.App) {
    // Global middleware (applied to all routes)
    app.Use(middleware.RequestLogger())
    app.Use(middleware.SecurityHeaders())

    // Health check (no auth required)
    app.Get("/health", handlers.HealthCheck)

    // Public routes
    public := app.Group("/api/v1")
    public.Post("/login", handlers.Login)
    public.Post("/register", handlers.Register)
    public.Post("/logout", handlers.Logout)

    // Protected routes (authentication required)
    protected := app.Group("/api/v1", middleware.RequireAuth())
    protected.Get("/profile", handlers.GetProfile)
    protected.Put("/profile", handlers.UpdateProfile)

    // Admin routes (authentication + admin permission required)
    admin := app.Group("/api/v1/admin",
        middleware.RequireAuth(),
        middleware.RequirePermission("admin"))
    admin.Get("/users", handlers.ListUsers)
    admin.Delete("/users/:id", handlers.DeleteUser)
}
```

---

## Error Handling Pattern

### Custom Error Handler

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
    // Log all errors with context
    Logger.Error().
        Str("who", "system:error-handler").
        Str("what", "caught application error").
        Str("why", "request processing failed").
        Str("where", "middleware:error-handler").
        Err(err).
        Str("path", c.Path()).
        Str("method", c.Method()).
        Str("ip", c.IP()).
        Msg("Application error occurred")

    code := fiber.StatusInternalServerError

    if e, ok := err.(*fiber.Error); ok {
        code = e.Code
    }

    return c.Status(code).JSON(AppError{
        Code:    "ERROR",
        Message: "An error occurred processing your request",
    })
}
```

### Error Handling in Handlers

```go
// internal/api/handlers/user.go
func GetProfile(c *fiber.Ctx) error {
    user := c.Locals("user").(*models.User)

    utils.Logger.Info().
        Str("who", fmt.Sprintf("user:%s", user.Email)).
        Str("what", "retrieved user profile").
        Str("why", "user requested profile data").
        Str("where", "handlers:get-profile").
        Str("user_id", user.UserID).
        Msg("Profile retrieved successfully")

    return c.JSON(user)
}

func UpdateProfile(c *fiber.Ctx) error {
    user := c.Locals("user").(*models.User)

    var req UpdateProfileRequest
    if err := c.BodyParser(&req); err != nil {
        utils.Logger.Warn().
            Str("who", fmt.Sprintf("user:%s", user.Email)).
            Str("what", "failed to parse request").
            Str("why", "invalid JSON in request body").
            Str("where", "handlers:update-profile").
            Msg("Request parsing failed")

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

    // Update user
    if err := userService.UpdateUser(c.Context(), user, &req); err != nil {
        utils.Logger.Error().
            Str("who", fmt.Sprintf("user:%s", user.Email)).
            Str("what", "failed to update profile").
            Str("why", "database operation failed").
            Str("where", "handlers:update-profile").
            Err(err).
            Msg("Profile update failed")

        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to update profile",
        })
    }

    utils.Logger.Info().
        Str("who", fmt.Sprintf("user:%s", user.Email)).
        Str("what", "updated user profile").
        Str("why", "user submitted profile changes").
        Str("where", "handlers:update-profile").
        Msg("Profile updated successfully")

    return c.JSON(fiber.Map{
        "message": "Profile updated successfully",
        "user": user,
    })
}
```

---

## Naming Conventions

### Files and Packages

- **Package names**: lowercase, single word, no underscores
  - ✅ `package handlers`
  - ❌ `package user_handlers`

- **File names**: lowercase with underscores
  - ✅ `user_service.go`
  - ✅ `auth_middleware.go`
  - ❌ `UserService.go`

### Variables and Functions

- **Exported** (public): PascalCase
  - `func CreateUser()`
  - `type UserService struct`

- **Unexported** (private): camelCase
  - `func hashPassword()`
  - `var sessionDuration`

- **Constants**: PascalCase or ALL_CAPS
  - `const MaxRetries = 3`
  - `const SESSION_DURATION = 24 * time.Hour`

---

## Handler Structure

### Standard Handler Pattern

```go
func HandlerName(c *fiber.Ctx) error {
    // 1. Extract user/context
    user := c.Locals("user").(*models.User) // if authenticated

    // 2. Parse request
    var req RequestType
    if err := c.BodyParser(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
    }

    // 3. Validate request
    if err := utils.ValidateStruct(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": err.Error()})
    }

    // 4. Call service layer
    result, err := service.DoSomething(c.Context(), &req)
    if err != nil {
        // Log error
        utils.Logger.Error().
            Str("who", "...").
            Str("what", "...").
            Str("why", "...").
            Str("where", "...").
            Err(err).
            Msg("...")

        return c.Status(500).JSON(fiber.Map{"error": "Internal error"})
    }

    // 5. Return response
    return c.JSON(result)
}
```

---

## Service Layer Pattern

### Service Structure

```go
// internal/service/user_service.go
package service

type UserService struct {
    userRepo    *repository.UserRepository
    sessionRepo *repository.SessionRepository
}

func NewUserService(userRepo *repository.UserRepository, sessionRepo *repository.SessionRepository) *UserService {
    return &UserService{
        userRepo:    userRepo,
        sessionRepo: sessionRepo,
    }
}

func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
    utils.Logger.Debug().
        Str("who", "system:user-service").
        Str("what", "creating new user").
        Str("why", "user registration in progress").
        Str("where", "service:user-service").
        Str("email", req.Email).
        Msg("User creation initiated")

    // Business logic here
    user := &models.User{
        UserID:   uuid.New().String(),
        Email:    req.Email,
        Username: req.Username,
        // ...
    }

    // Hash password
    if err := user.HashPassword(req.Password); err != nil {
        return nil, fmt.Errorf("failed to hash password: %w", err)
    }

    // Save to database
    if err := s.userRepo.Create(ctx, user); err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }

    utils.Logger.Info().
        Str("who", fmt.Sprintf("user:%s", user.Email)).
        Str("what", "created user account").
        Str("why", "user registration completed").
        Str("where", "service:user-service").
        Str("user_id", user.UserID).
        Msg("User created successfully")

    return user, nil
}
```

---

## Dependency Injection Pattern

### Constructor Injection

```go
// main.go
func init() {
    // Initialize repositories
    userRepo := repository.NewUserRepository(dynamoClient, "users-table")
    sessionRepo := repository.NewSessionRepository(dynamoClient, "sessions-table")

    // Initialize services
    userService := service.NewUserService(userRepo, sessionRepo)
    authService := service.NewAuthService(userRepo, sessionRepo)

    // Initialize handlers
    handlers := api.NewHandlers(userService, authService)

    // Setup routes
    routes.Setup(app, handlers)
}
```

---

## Testing Patterns

### Unit Test Structure

```go
// internal/service/user_service_test.go
package service_test

import (
    "context"
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

func TestUserService_CreateUser(t *testing.T) {
    // Arrange
    mockRepo := new(MockUserRepository)
    service := service.NewUserService(mockRepo, nil)

    req := &CreateUserRequest{
        Email:    "test@example.com",
        Username: "testuser",
        Password: "SecurePass123!",
    }

    mockRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).
        Return(nil)

    // Act
    user, err := service.CreateUser(context.Background(), req)

    // Assert
    assert.NoError(t, err)
    assert.NotNil(t, user)
    assert.Equal(t, req.Email, user.Email)
    mockRepo.AssertExpectations(t)
}
```

### Table-Driven Tests

```go
func TestValidateEmail(t *testing.T) {
    tests := []struct {
        name    string
        email   string
        want    bool
    }{
        {"valid email", "test@example.com", true},
        {"invalid no @", "testexample.com", false},
        {"invalid no domain", "test@", false},
        {"empty", "", false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := validateEmail(tt.email)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

---

## Code Quality Standards

### Required Checks

1. **Linting**: All code must pass `golangci-lint`
   ```bash
   golangci-lint run ./...
   ```

2. **Formatting**: Use `gofmt` or `goimports`
   ```bash
   gofmt -w .
   goimports -w .
   ```

3. **Testing**: Minimum 80% coverage
   ```bash
   go test -cover ./...
   ```

4. **Security Scanning**: Pass `gosec`
   ```bash
   gosec ./...
   ```

### Code Review Checklist

- [ ] All logs include who/what/why/where
- [ ] Error handling implemented
- [ ] Input validation present
- [ ] Tests included
- [ ] No hardcoded credentials
- [ ] Context propagated through calls
- [ ] Sensitive data not logged
- [ ] Proper HTTP status codes used

---

## Related Documentation

- **Architecture Standards**: [ARCHITECTURE_STANDARDS.md](./ARCHITECTURE_STANDARDS.md)
- **Security Standards**: [SECURITY_STANDARDS.md](./SECURITY_STANDARDS.md)
- **Logging Standards**: [LOGGING_STANDARDS.md](./LOGGING_STANDARDS.md)
- **Database Standards**: [DATABASE_STANDARDS.md](./DATABASE_STANDARDS.md)

---

**Version:** 1.0
**Maintainer:** DevOps/SRE Team
