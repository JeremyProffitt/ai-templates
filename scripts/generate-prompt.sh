#!/bin/bash
#
# generate-prompt.sh
# Generates a customized Claude Code prompt for your project
#
# Usage: ./generate-prompt.sh <project-name> [options]
# Example: ./generate-prompt.sh recipe-api --auth --crud recipes --search

set -e

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }

# Default values
PROJECT_NAME=""
INCLUDE_AUTH=false
CRUD_MODELS=()
INCLUDE_SEARCH=false
INCLUDE_ADMIN=false
INCLUDE_FAVORITES=false
INCLUDE_UPLOAD=false
DESCRIPTION=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --auth)
            INCLUDE_AUTH=true
            shift
            ;;
        --crud)
            CRUD_MODELS+=("$2")
            shift 2
            ;;
        --search)
            INCLUDE_SEARCH=true
            shift
            ;;
        --admin)
            INCLUDE_ADMIN=true
            shift
            ;;
        --favorites)
            INCLUDE_FAVORITES=true
            shift
            ;;
        --upload)
            INCLUDE_UPLOAD=true
            shift
            ;;
        --description)
            DESCRIPTION="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 <project-name> [options]"
            echo ""
            echo "Options:"
            echo "  --auth                Include authentication endpoints"
            echo "  --crud <model>        Add CRUD endpoints for model (can be used multiple times)"
            echo "  --search              Include search functionality"
            echo "  --admin               Include admin endpoints"
            echo "  --favorites           Include favorites feature"
            echo "  --upload              Include file upload capability"
            echo "  --description <text>  Project description"
            echo ""
            echo "Example:"
            echo "  $0 recipe-api --auth --crud recipes --crud categories --search --favorites"
            exit 0
            ;;
        *)
            if [ -z "$PROJECT_NAME" ]; then
                PROJECT_NAME="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$PROJECT_NAME" ]; then
    echo "Error: Project name required"
    echo "Usage: $0 <project-name> [options]"
    echo "Try: $0 --help"
    exit 1
fi

# Generate prompt
print_info "Generating Claude Code prompt for $PROJECT_NAME..."

cat <<EOF
Create a complete AWS Lambda Go/Fiber application following ai-templates/GENERATION_MASTER.md

Project Name: $PROJECT_NAME
$([ -n "$DESCRIPTION" ] && echo "Description: $DESCRIPTION")

Architecture:
- AWS Lambda with API Gateway
- GoFiber v2 framework
- DynamoDB for all data storage
- Cookie-based sessions
- Structured logging (who/what/why/where pattern)

EOF

# Data Models section
echo "Data Models:"
echo "- User: user_id (PK), email, username, password_hash, created_at, updated_at, is_active"

for model in "${CRUD_MODELS[@]}"; do
    MODEL_UPPER=$(echo "$model" | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    echo "- ${MODEL_UPPER}: ${model}_id (PK), [DEFINE FIELDS], created_by, created_at, updated_at"
done

if [ "$INCLUDE_FAVORITES" = true ]; then
    echo "- Favorite: user_id (PK), ${CRUD_MODELS[0]}_id (SK), created_at"
fi

echo ""

# API Endpoints section
echo "API Endpoints:"
echo ""

if [ "$INCLUDE_AUTH" = true ]; then
    cat <<'EOF'
Public Endpoints (No Authentication):
- GET /health - Health check
- POST /api/v1/auth/register - User registration
  Request: { email, username, password, name }
  Response: { user_id, message }
- POST /api/v1/auth/login - User login
  Request: { email, password }
  Response: { message } + session cookie
- POST /api/v1/auth/logout - User logout
  Response: { message }

EOF
fi

if [ ${#CRUD_MODELS[@]} -gt 0 ]; then
    echo "Protected Endpoints (Requires Authentication):"
    for model in "${CRUD_MODELS[@]}"; do
        MODEL_UPPER=$(echo "$model" | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
        cat <<EOF
- GET /api/v1/${model} - List all ${model} with pagination
  Query params: page, limit, sort
  Response: { ${model}: [...], total, page, limit }
- GET /api/v1/${model}/:id - Get single ${model}
  Response: { ${model}: {...} }
- POST /api/v1/${model} - Create new ${model}
  Request: { [${model} fields] }
  Response: { ${model}_id, message }
- PUT /api/v1/${model}/:id - Update ${model}
  Request: { [${model} fields] }
  Response: { message }
- DELETE /api/v1/${model}/:id - Delete ${model}
  Response: { message }

EOF
    done
fi

if [ "$INCLUDE_SEARCH" = true ]; then
    cat <<EOF
- GET /api/v1/${CRUD_MODELS[0]}/search - Search ${CRUD_MODELS[0]}
  Query params: q (search term), category, tags
  Response: { results: [...], total }

EOF
fi

if [ "$INCLUDE_FAVORITES" = true ]; then
    cat <<EOF
- POST /api/v1/${CRUD_MODELS[0]}/:id/favorite - Add to favorites
  Response: { message }
- DELETE /api/v1/${CRUD_MODELS[0]}/:id/favorite - Remove from favorites
  Response: { message }
- GET /api/v1/${CRUD_MODELS[0]}/favorites - Get user's favorites
  Response: { favorites: [...] }

EOF
fi

echo "- GET /api/v1/profile - Get user profile"
echo "- PUT /api/v1/profile - Update user profile"
echo ""

if [ "$INCLUDE_ADMIN" = true ]; then
    cat <<EOF
Admin Endpoints (Requires Admin Permission):
- GET /api/v1/admin/users - List all users
- GET /api/v1/admin/users/:id - Get user details
- PUT /api/v1/admin/users/:id - Update user (including permissions)
- DELETE /api/v1/admin/users/:id - Delete user
- GET /api/v1/admin/stats - System statistics

EOF
fi

# Features section
cat <<EOF
Required Features:
- Input validation on all endpoints (sanitize inputs, check types, validate lengths)
- Authentication middleware for protected routes
- Authorization middleware for admin routes (if applicable)
$([ "$INCLUDE_AUTH" = true ] && echo "- Session management with DynamoDB (24-hour expiration)")
- Pagination on all list endpoints (default: page=1, limit=20)
- Error handling that never exposes internal details
- CORS configuration
- Security headers middleware

Critical Requirements:
1. LOGGING PATTERN (MOST IMPORTANT!):
   Every log MUST include these four fields:
   - who: Actor (e.g., "user:john@example.com", "system:scheduler")
   - what: Action in past tense (e.g., "created ${CRUD_MODELS[0]}", "deleted user")
   - why: Business reason in ONE sentence max 100 chars
   - where: Component (e.g., "handlers:create-${CRUD_MODELS[0]}", "service:user-service")

   Example:
   Logger.Info().
       Str("who", fmt.Sprintf("user:%s", user.Email)).
       Str("what", "created ${CRUD_MODELS[0]}").
       Str("why", "user submitted new ${CRUD_MODELS[0]} via API").
       Str("where", "handlers:create-${CRUD_MODELS[0]}").
       Msg("${MODEL_UPPER} created successfully")

2. ERROR HANDLING:
   - Never expose internal errors to clients
   - Always log errors with full context
   - Return appropriate HTTP status codes
   - Use generic error messages for clients

3. SECURITY:
   - Validate all inputs
   - Sanitize all outputs
   - Use prepared statements for DynamoDB queries
   - Implement rate limiting for sensitive endpoints
   - Never log passwords or tokens

4. TESTING:
   - Unit tests for all business logic
   - Integration tests for API endpoints
   - Minimum 80% code coverage
   - Table-driven tests where appropriate

5. DATABASE:
   - DynamoDB tables with appropriate indexes
   - GSIs for alternate access patterns
   - TTL for session expiration
   - Pagination using DynamoDB query patterns

DynamoDB Tables Required:
- users (PK: user_id, GSI: email, GSI: username)
- sessions (PK: session_id, GSI: user_id, TTL: expires_at)
$(for model in "${CRUD_MODELS[@]}"; do
    echo "- ${model} (PK: ${model}_id, GSI: created_by)"
done)
$([ "$INCLUDE_FAVORITES" = true ] && echo "- favorites (PK: user_id, SK: ${CRUD_MODELS[0]}_id)")

SAM Template Requirements:
- Lambda function with appropriate memory and timeout
- API Gateway with CORS
- All DynamoDB tables with indexes
- CloudWatch log groups
- IAM roles with least-privilege permissions

GitHub Actions Workflow:
- Run tests on pull requests
- Deploy to dev on push to develop branch
- Deploy to prod on push to main branch
- Security scanning with gosec

Standards to Follow:
- Architecture: ai-templates/standards/ARCHITECTURE_STANDARDS.md
- Logging: ai-templates/standards/LOGGING_STANDARDS.md (CRITICAL!)
- Security: ai-templates/standards/SECURITY_STANDARDS.md
- Coding: ai-templates/standards/CODING_STANDARDS.md
- Database: ai-templates/standards/DATABASE_STANDARDS.md

Deliverables:
1. Complete Go application following structure
2. All handlers with proper logging
3. DynamoDB repositories
4. Service layer with business logic
5. Middleware for auth, logging, security
6. Unit and integration tests
7. SAM template with all resources
8. GitHub Actions workflow
9. Makefile with build/deploy commands
10. README with setup instructions

IMPORTANT: Review ai-templates/GENERATION_MASTER.md for complete context and patterns before generating code.
EOF

print_success "Prompt generated successfully!"
echo ""
print_info "To use with Claude Code:"
echo "  ./generate-prompt.sh $PROJECT_NAME $* > .claude-prompt.txt"
echo "  claude code \"\$(cat .claude-prompt.txt)\""
