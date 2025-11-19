# Claude Code Prompt Template for AWS Lambda Go/Fiber Applications

## Instructions for Claude Code

Create a complete AWS Lambda application following these exact specifications. Reference the PROJECT_STANDARDS.md file for detailed implementation patterns.

## Project Specifications

### Core Requirements
- **Language**: Go 1.21+
- **Framework**: GoFiber v2 with aws-lambda-go-api-proxy/fiber adapter
- **Runtime**: AWS Lambda with API Gateway
- **Database**: DynamoDB for sessions and user data
- **Authentication**: Cookie-based sessions with DynamoDB storage
- **Deployment**: AWS SAM with GitHub Actions CI/CD
- **Logging**: Verbose structured logging with zerolog in json format

### Project Name
[PROJECT_NAME] # Replace with your project name

### Business Requirements
[Describe your specific business requirements here]

### Required API Endpoints

#### Public Endpoints (No Authentication)
- `POST /api/v1/register` - User registration with email/username/password
- `POST /api/v1/login` - User authentication returning session cookie
- `POST /api/v1/logout` - Session termination
- `POST /api/v1/forgot-password` - Password reset request
- `POST /api/v1/reset-password` - Password reset with token

#### Protected Endpoints (Authentication Required)
- `GET /api/v1/profile` - Get current user profile
- `PUT /api/v1/profile` - Update user profile
- `POST /api/v1/change-password` - Change password

#### Admin Endpoints (Admin Permission Required)
- `GET /api/v1/admin/users` - List all users with pagination
- `GET /api/v1/admin/users/:id` - Get specific user details
- `PUT /api/v1/admin/users/:id` - Update user (including permissions)
- `DELETE /api/v1/admin/users/:id` - Delete user
- `GET /api/v1/admin/stats` - System statistics

### Implementation Requirements

1. **Project Structure**
   - Follow the exact structure defined in PROJECT_STANDARDS.md
   - Implement clean architecture with proper separation of concerns
   - Use dependency injection for testability

2. **Authentication & Authorization**
   - Implement secure password hashing with bcrypt (cost 14)
   - Generate cryptographically secure session IDs
   - Store sessions in DynamoDB with 24-hour TTL
   - Implement RBAC with roles: user, editor, admin
   - Add rate limiting for login attempts

3. **Database Design**
   - Create DynamoDB tables as specified
   - Implement proper error handling for DynamoDB operations
   - Use batch operations where appropriate
   - Implement pagination for list operations

4. **Error Handling**
   - Implement comprehensive error handling
   - Return and log appropriate HTTP status codes
   - Log all errors with context
   - Never expose internal errors to clients
   - All functiontions wrapped in a try/catch

5. **Logging Requirements** (CRITICAL - See LOGGING_STANDARDS.md)
   - **MANDATORY**: Every log MUST include four human-readable fields:
     - `who`: Actor/subject (e.g., "user:john@example.com", "system:scheduler") - Max 50 chars
     - `what`: Action performed in past tense (e.g., "created user account") - Max 60 chars
     - `why`: Business reason in ONE sentence (e.g., "user registration completed") - Max 100 chars
     - `where`: System/component (e.g., "auth-service:login-handler") - Max 50 chars
   - Log every request and response with who/what/why/where
   - Include request ID in all logs for tracing
   - Log all database operations with duration
   - Log all authentication attempts with risk context
   - Use structured JSON logging with zerolog
   - Log response times for performance monitoring
   - **Format Example**:
     ```go
     Logger.Info().
         Str("who", "user:john@example.com").
         Str("what", "updated user profile").
         Str("why", "user submitted profile changes via API").
         Str("where", "user-service:profile-handler").
         Msg("Profile updated successfully")
     ```
   - **NEVER** use cryptic abbreviations or machine-only logs
   - **ALWAYS** make logs immediately understandable by humans

6. **Security Requirements**
   - Implement CORS properly
   - Add security headers middleware
   - Validate all inputs
   - Sanitize outputs
   - Implement CSRF protection for state-changing operations
   - Use secure cookie flags
   - Single JWT Token generated in pipeline and used for all services, environment variable JWT_SECRET

7. **Testing Requirements**
   - Unit tests for all business logic (minimum 80% coverage)
   - Integration tests for API endpoints
   - Mock DynamoDB for unit tests
   - Table-driven tests where appropriate
   - Benchmark critical paths
   - Testing build into pipeline, must pass to deploy

8. **Performance Optimizations**
   - Minimize cold start time
   - Reuse DynamoDB client
   - Implement connection pooling
   - Use compression middleware
   - Cache frequently accessed data in memory

## File Deliverables

Create these files with complete implementation:

### Application Code
```
cmd/lambda/main.go                    # Lambda handler entry point
internal/api/handlers/auth.go         # Authentication handlers
internal/api/handlers/user.go         # User handlers  
internal/api/handlers/admin.go        # Admin handlers
internal/api/handlers/health.go       # Health check handler
internal/api/middleware/auth.go       # Authentication middleware
internal/api/middleware/logging.go    # Logging middleware
internal/api/middleware/security.go   # Security headers middleware
internal/api/middleware/ratelimit.go  # Rate limiting middleware
internal/api/routes/routes.go         # Route definitions
internal/auth/authenticator.go        # Authentication logic
internal/auth/permissions.go          # RBAC implementation
internal/auth/session.go              # Session management
internal/config/config.go             # Configuration management
internal/database/dynamodb.go         # DynamoDB client
internal/database/models/user.go      # User model
internal/database/models/session.go   # Session model
internal/database/repository/user.go  # User repository
internal/database/repository/session.go # Session repository
internal/service/user_service.go      # User business logic
internal/service/admin_service.go     # Admin business logic
internal/utils/logger.go              # Logger setup
internal/utils/errors.go              # Error types and handling
internal/utils/validation.go          # Input validation
internal/utils/response.go            # Response helpers
```

### Tests
```
internal/api/handlers/auth_test.go
internal/api/handlers/user_test.go
internal/api/handlers/admin_test.go
internal/auth/authenticator_test.go
internal/service/user_service_test.go
tests/integration/api_test.go
tests/integration/auth_flow_test.go
```

### Configuration Files
```
go.mod                          # Go module file
go.sum                          # Go dependencies
.env.example                    # Example environment variables
.gitignore                      # Git ignore file
.golangci.yml                   # Linter configuration
```

### Deployment Files
```
deployments/template.yaml       # SAM template
deployments/samconfig.toml      # SAM configuration
.github/workflows/deploy.yml    # GitHub Actions workflow
.github/workflows/test.yml      # Test workflow
Makefile                        # Build and deploy commands
Dockerfile                      # For local testing
docker-compose.yml              # Local development setup
```

### Documentation
```
README.md                       # Project documentation
API.md                         # API documentation
DEPLOYMENT.md                  # Deployment guide
CONTRIBUTING.md                # Contribution guidelines
```

### Scripts
```
scripts/seed.go                # Seed test data
scripts/migrate.go             # Database migrations
scripts/create-admin.go        # Create admin user
```

## Code Generation Instructions

1. Generate all files with complete, production-ready implementation
2. Include comprehensive error handling and logging
3. Follow Go best practices and idioms
4. Use meaningful variable and function names
5. Add helpful comments for complex logic
6. Implement all endpoints with actual logic, not placeholders
7. Include input validation for all endpoints
8. Add pagination where applicable
9. Implement proper transaction handling
10. Follow the exact patterns from PROJECT_STANDARDS.md

## Additional Features to Implement

- [ ] Request ID tracking
- [ ] Correlation ID for distributed tracing
- [ ] Metrics collection (request count, latency, errors)
- [ ] Circuit breaker for external services
- [ ] Retry logic with exponential backoff
- [ ] Graceful degradation
- [ ] API versioning
- [ ] OpenAPI/Swagger documentation
- [ ] Audit logging for sensitive operations
- [ ] Data encryption at rest

## Environment Variables Required

```bash
# Service Configuration
SERVICE_NAME=your-service-name
ENVIRONMENT=dev|staging|prod
VERSION=1.0.0
LOG_LEVEL=VERBOSE

# AWS Configuration
AWS_REGION=us-east-1
USERS_TABLE=${ENVIRONMENT}-users
SESSIONS_TABLE=${ENVIRONMENT}-sessions
PERMISSIONS_TABLE=${ENVIRONMENT}-permissions

# Security Configuration
SESSION_DURATION=24h
COOKIE_SECURE=true
COOKIE_HTTPONLY=true
COOKIE_SAMESITE=Strict
JWT_SECRET=${SECRET_VALUE}
ENCRYPTION_KEY=${SECRET_VALUE}

# Rate Limiting
MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW=15m

# Features
MFA_ENABLED=false
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_REQUIRE_NUMBER=true
PASSWORD_REQUIRE_UPPERCASE=true
```

## Success Criteria

The generated application must:
1. ✅ Compile without errors
2. ✅ Pass all tests
3. ✅ Deploy successfully to AWS Lambda
4. ✅ Handle authentication correctly
5. ✅ Implement all specified endpoints
6. ✅ Follow security best practices
7. ✅ Include comprehensive logging
8. ✅ Have proper error handling
9. ✅ Be production-ready
10. ✅ Follow PROJECT_STANDARDS.md exactly

## Notes for Claude Code

- This is a production system that will handle real user data
- Security is paramount - never store plaintext passwords or expose sensitive data
- Performance matters - optimize for Lambda cold starts
- The code will be reviewed by a senior engineering team
- Follow Go idioms and best practices
- Make the code maintainable and well-documented
- Consider edge cases and error scenarios
- Implement proper cleanup and resource management
- Use context for cancellation and timeouts
- Test thoroughly before marking as complete

---

Generate the complete application now, ensuring all files are production-ready and fully implemented.
