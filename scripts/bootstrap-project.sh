#!/bin/bash
#
# bootstrap-project.sh
# Creates a new Go Lambda project from ai-templates
#
# Usage: ./bootstrap-project.sh <project-name>
# Example: ./bootstrap-project.sh recipe-api

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }

# Check arguments
if [ $# -eq 0 ]; then
    print_error "Project name required"
    echo "Usage: $0 <project-name>"
    echo "Example: $0 recipe-api"
    exit 1
fi

PROJECT_NAME=$1
TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="../$PROJECT_NAME"

print_info "Bootstrapping new project: $PROJECT_NAME"
print_info "Template directory: $TEMPLATE_DIR"
print_info "Target directory: $TARGET_DIR"
echo

# Check if project already exists
if [ -d "$TARGET_DIR" ]; then
    print_error "Project directory already exists: $TARGET_DIR"
    exit 1
fi

# Create project directory
print_info "Creating project directory..."
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"
print_success "Project directory created"

# Initialize Go module
print_info "Initializing Go module..."
go mod init "$PROJECT_NAME" 2>/dev/null || true
print_success "Go module initialized"

# Create directory structure
print_info "Creating directory structure..."
mkdir -p cmd/lambda
mkdir -p internal/api/{handlers,middleware,routes}
mkdir -p internal/auth
mkdir -p internal/config
mkdir -p internal/database/{models,repository}
mkdir -p internal/service
mkdir -p internal/utils
mkdir -p deployments
mkdir -p tests/{unit,integration}
mkdir -p scripts
print_success "Directory structure created"

# Copy configuration files
print_info "Copying configuration files..."
cp "$TEMPLATE_DIR/config/.env.example" .env.example
cp "$TEMPLATE_DIR/config/.gitignore" .gitignore
print_success "Configuration files copied"

# Create README
print_info "Creating README.md..."
cat > README.md <<EOF
# $PROJECT_NAME

Generated from ai-templates on $(date +%Y-%m-%d)

## Quick Start

\`\`\`bash
# Install dependencies
go mod download

# Run tests
make test

# Deploy to dev
make deploy-dev
\`\`\`

## Project Structure

\`\`\`
$PROJECT_NAME/
├── cmd/lambda/          # Lambda handler entry point
├── internal/
│   ├── api/             # HTTP layer
│   ├── auth/            # Authentication
│   ├── database/        # Data access
│   ├── service/         # Business logic
│   └── utils/           # Utilities
├── deployments/         # SAM templates
└── tests/               # Test suites
\`\`\`

## Environment Variables

Copy \`.env.example\` to \`.env\` and update values:

\`\`\`bash
cp .env.example .env
# Edit .env with your configuration
\`\`\`

## Deployment

\`\`\`bash
# Deploy to development
make deploy-dev

# Deploy to production
make deploy-prod
\`\`\`

## Documentation

See [ai-templates](../ai-templates/README.md) for complete documentation.
EOF
print_success "README.md created"

# Create Makefile
print_info "Creating Makefile..."
cat > Makefile <<'EOF'
.PHONY: build clean deploy test lint run-local

BINARY_NAME=bootstrap
LAMBDA_PACKAGE=lambda-deployment.zip

build:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
		-ldflags="-s -w" \
		-tags lambda.norpc \
		-o $(BINARY_NAME) cmd/lambda/main.go

test:
	go test -v -race -coverprofile=coverage.txt ./...
	go tool cover -func=coverage.txt

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
	rm -f coverage.txt

.DEFAULT_GOAL := build
EOF
print_success "Makefile created"

# Create initial prompt file
print_info "Creating Claude Code prompt..."
cat > .claude-prompt.txt <<EOF
Create a complete AWS Lambda Go/Fiber application following ai-templates/GENERATION_MASTER.md

Project Name: $PROJECT_NAME

Requirements:
[EDIT THIS FILE TO ADD YOUR SPECIFIC REQUIREMENTS]

Example requirements:
- User authentication (register, login, logout)
- CRUD operations for main resources
- DynamoDB tables with appropriate indexes
- Input validation on all endpoints
- Logging with who/what/why/where pattern
- Tests with 80%+ coverage
- SAM template for deployment
- GitHub Actions workflow

Data Models:
[DEFINE YOUR DATA MODELS HERE]

API Endpoints:
[LIST YOUR API ENDPOINTS HERE]

Follow all standards from ai-templates:
- Architecture: standards/ARCHITECTURE_STANDARDS.md
- Logging: standards/LOGGING_STANDARDS.md (CRITICAL!)
- Security: standards/SECURITY_STANDARDS.md
- Coding: standards/CODING_STANDARDS.md
EOF
print_success "Claude prompt template created"

# Print summary
echo
print_success "Project $PROJECT_NAME bootstrapped successfully!"
echo
print_info "Next steps:"
echo "  1. cd $TARGET_DIR"
echo "  2. Edit .claude-prompt.txt with your requirements"
echo "  3. Run: claude code \"\$(cat .claude-prompt.txt)\""
echo "  4. Configure .env file"
echo "  5. Deploy: make deploy-dev"
echo
print_info "Or use the prompt generator script:"
echo "  ../ai-templates/scripts/generate-prompt.sh $PROJECT_NAME --help"
echo
