# Automation Scripts

Helper scripts to streamline project generation and deployment.

---

## Available Scripts

### 1. bootstrap-project.sh

**Purpose:** Create a new project from scratch with proper structure

**Usage:**
```bash
./bootstrap-project.sh <project-name>
```

**Example:**
```bash
./bootstrap-project.sh recipe-api
```

**What it does:**
- Creates project directory
- Initializes Go module
- Creates standard directory structure
- Copies configuration templates
- Generates initial prompt file
- Creates Makefile and README

**Output:**
```
../recipe-api/
├── go.mod
├── .env.example
├── .gitignore
├── .claude-prompt.txt
├── README.md
├── Makefile
└── [directory structure]
```

---

### 2. generate-prompt.sh

**Purpose:** Generate customized Claude Code prompt based on requirements

**Usage:**
```bash
./generate-prompt.sh <project-name> [options]
```

**Options:**
- `--auth` - Include authentication endpoints
- `--crud <model>` - Add CRUD for a model (repeatable)
- `--search` - Include search functionality
- `--admin` - Include admin endpoints
- `--favorites` - Include favorites feature
- `--upload` - Include file upload capability
- `--description <text>` - Project description

**Examples:**

Simple API:
```bash
./generate-prompt.sh todo-api --auth --crud tasks
```

Recipe website:
```bash
./generate-prompt.sh recipe-api \
  --auth \
  --crud recipes \
  --crud categories \
  --search \
  --favorites \
  --description "Recipe collection website"
```

E-commerce:
```bash
./generate-prompt.sh shop-api \
  --auth \
  --crud products \
  --crud orders \
  --search \
  --admin \
  --description "E-commerce platform"
```

**Save to file:**
```bash
./generate-prompt.sh recipe-api --auth --crud recipes > recipe-prompt.txt
```

**Use with Claude Code:**
```bash
claude code "$(./generate-prompt.sh recipe-api --auth --crud recipes)"
```

---

### 3. test-api.sh

**Purpose:** Test deployed API endpoints

**Usage:**
```bash
./test-api.sh <api-url>
```

**Example:**
```bash
./test-api.sh https://abc123.execute-api.us-east-1.amazonaws.com/Prod
```

**What it tests:**
1. Health check endpoint
2. User registration
3. User login (saves session cookie)
4. Authenticated profile access
5. Unauthorized access (without cookie)
6. User logout

**Output:**
```
Testing API: https://abc123...
TEST: Health check
PASS Health check returned 200
TEST: User registration
PASS User registration successful
  User ID: usr_abc123
TEST: User login
PASS User login successful
...
All tests passed!
```

---

## Common Workflows

### Workflow 1: Start New Project (Quick)

```bash
# 1. Bootstrap
./bootstrap-project.sh my-api

# 2. Generate prompt and save
./generate-prompt.sh my-api --auth --crud items > my-api-prompt.txt

# 3. Generate with Claude
cd ../my-api
claude code "$(cat my-api-prompt.txt)"

# 4. Deploy
make deploy-dev

# 5. Test
../ai-templates/scripts/test-api.sh <your-api-url>
```

**Time:** ~10 minutes

---

### Workflow 2: Recipe Website Example

```bash
# Generate recipe API prompt
cd ai-templates
./generate-prompt.sh recipe-api \
  --auth \
  --crud recipes \
  --crud categories \
  --search \
  --favorites \
  --description "Recipe collection and editing website" \
  > recipe-prompt.txt

# Generate with Claude Code
claude code "$(cat recipe-prompt.txt)"

# Configure
cd ../recipe-api
cp ../ai-templates/config/.env.example .env
# Edit .env with your AWS config

# Deploy
make deploy-dev

# Test
../ai-templates/scripts/test-api.sh $(aws cloudformation describe-stacks \
  --stack-name recipe-api-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
  --output text)
```

---

### Workflow 3: Custom Complex API

```bash
# 1. Bootstrap with structure
./bootstrap-project.sh my-complex-api

# 2. Edit the prompt file manually
cd ../my-complex-api
nano .claude-prompt.txt
# Add your custom requirements

# 3. Generate
claude code "$(cat .claude-prompt.txt)"

# 4. Deploy and test
make deploy-dev
```

---

## Script Details

### bootstrap-project.sh

**Dependencies:**
- Go 1.21+
- git

**Files Created:**
- `go.mod` - Go module file
- `.env.example` - Environment template
- `.gitignore` - Git ignore patterns
- `.claude-prompt.txt` - Initial prompt template
- `README.md` - Project documentation
- `Makefile` - Build/deploy automation

**Directory Structure:**
```
project/
├── cmd/lambda/
├── internal/
│   ├── api/{handlers,middleware,routes}
│   ├── auth/
│   ├── config/
│   ├── database/{models,repository}
│   ├── service/
│   └── utils/
├── deployments/
├── tests/{unit,integration}
└── scripts/
```

---

### generate-prompt.sh

**Output Format:**
Generates a complete Claude Code prompt with:
- Project name and description
- Data models based on --crud flags
- API endpoints (public, protected, admin)
- Business rules
- Logging requirements (who/what/why/where)
- DynamoDB table specifications
- Testing requirements
- References to standards

**Customization:**
Edit the script to:
- Add custom data models
- Add more endpoint templates
- Modify business rules
- Add additional features

---

### test-api.sh

**Requirements:**
- curl
- API URL (from CloudFormation outputs)

**Test Sequence:**
1. Health check (GET /health)
2. Register (POST /api/v1/auth/register)
3. Login (POST /api/v1/auth/login)
4. Get profile (GET /api/v1/profile) with cookie
5. Test unauthorized (GET /api/v1/profile) without cookie
6. Logout (POST /api/v1/auth/logout)

**Customization:**
Add tests for your specific endpoints:
```bash
# Add after login test
print_test "Create recipe"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/recipes" \
    -H "Content-Type: application/json" \
    -b "$COOKIE_JAR" \
    -d '{"title": "Test Recipe", ...}')
```

---

## Tips & Best Practices

### 1. Save Prompts for Reuse

```bash
# Generate and save
./generate-prompt.sh my-api --auth --crud items > prompts/my-api.txt

# Reuse later
claude code "$(cat prompts/my-api.txt)"
```

### 2. Test Before Production

Always test the dev deployment before promoting to prod:

```bash
# Deploy to dev
make deploy-dev

# Test thoroughly
./scripts/test-api.sh <dev-api-url>

# If tests pass, deploy to prod
make deploy-prod
```

### 3. Version Control

Commit the generated prompt for documentation:

```bash
git add .claude-prompt.txt
git commit -m "Add Claude Code generation prompt"
```

### 4. Customize Scripts

Copy and modify scripts for your needs:

```bash
cp generate-prompt.sh custom-prompt.sh
# Edit custom-prompt.sh with your specific requirements
```

---

## Troubleshooting

### Script Permission Denied

```bash
chmod +x scripts/*.sh
```

### Claude Code Not Found

Install Claude Code CLI:
```bash
# Follow installation instructions from Claude
```

### AWS Credentials Not Configured

```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, Region
```

### Go Module Init Fails

```bash
# Run manually
go mod init your-project-name
```

---

## Future Scripts (Coming Soon)

- **deploy-helper.sh** - Automated deployment with validation
- **setup-aws.sh** - AWS resource setup automation
- **create-admin-user.sh** - Create admin user in deployed API
- **backup-dynamodb.sh** - Backup DynamoDB tables
- **migrate-data.sh** - Data migration helper

---

## Contributing

To add new scripts:

1. Follow naming convention: `verb-noun.sh`
2. Add help text (`--help` flag)
3. Use colored output (GREEN, RED, BLUE)
4. Add error handling (`set -e`)
5. Document in this README
6. Add example usage

---

## Resources

- **Usage Guide**: [../USAGE.md](../USAGE.md)
- **Recipe Example**: [../examples/RECIPE_WEBSITE_EXAMPLE.md](../examples/RECIPE_WEBSITE_EXAMPLE.md)
- **Generation Master**: [../GENERATION_MASTER.md](../GENERATION_MASTER.md)

---

**Maintained By:** DevOps/SRE Team
**Version:** 1.0
