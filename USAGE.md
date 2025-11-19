# How to Use This Repository to Generate Applications

**Step-by-step guide with practical example: Recipe Collection Website**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Detailed Walkthrough](#detailed-walkthrough)
3. [Recipe Website Example](#recipe-website-example)
4. [Using Automation Scripts](#using-automation-scripts)
5. [Customization Guide](#customization-guide)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start (5 Minutes)

### Option 1: Use Automation Script (Recommended)

```bash
# 1. Navigate to ai-templates
cd /path/to/ai-templates

# 2. Run the bootstrap script
./scripts/bootstrap-project.sh recipe-api

# 3. Follow the prompts to configure your project

# 4. Generate the application with Claude Code
claude code "$(cat .claude-prompt.txt)"

# 5. Deploy
cd ../recipe-api
make deploy-dev
```

### Option 2: Manual Generation

```bash
# 1. Use Claude Code with GENERATION_MASTER.md
claude code "Create a Lambda API following ai-templates/GENERATION_MASTER.md for a recipe collection website with endpoints for creating, reading, updating, and deleting recipes"

# 2. Configure and deploy
cd recipe-api
cp ../ai-templates/config/.env.example .env
# Edit .env with your values
make deploy-dev
```

---

## Detailed Walkthrough

### Step 1: Understand the Architecture

Before generating code, review the architecture:

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│             │      │              │      │             │
│  Web Client │────▶ │ API Gateway  │────▶ │  Lambda     │
│             │      │              │      │  (GoFiber)  │
└─────────────┘      └──────────────┘      └──────┬──────┘
                                                   │
                                                   ▼
                                            ┌─────────────┐
                                            │  DynamoDB   │
                                            │  - Users    │
                                            │  - Sessions │
                                            │  - Recipes  │
                                            └─────────────┘
```

**Key Points:**
- Serverless (no servers to manage)
- Stateless Lambda functions
- All data in DynamoDB
- Cookie-based authentication
- Structured logging (who/what/why/where)

### Step 2: Define Your Requirements

For the recipe website example, define:

**Data Model:**
- Users (authentication)
- Recipes (with ingredients, instructions)
- Categories/Tags
- User favorites

**API Endpoints:**
- Authentication (login, register, logout)
- Recipes CRUD (create, read, update, delete)
- Search and filter
- User profile management

**Features:**
- User authentication
- Recipe ownership (users own their recipes)
- Public/private recipes
- Image upload for recipes
- Rating system

### Step 3: Prepare Your Prompt

Use the automation script or create manually:

```bash
# Using automation script
cd ai-templates
./scripts/generate-prompt.sh recipe-api > recipe-prompt.txt

# Or create manually using template
cat GENERATION_MASTER.md > recipe-prompt.txt
# Edit to add recipe-specific requirements
```

### Step 4: Generate with Claude Code

```bash
claude code "$(cat recipe-prompt.txt)"
```

Or interactively:

```bash
claude code
```

Then paste:
```
Create a Lambda API following ai-templates/GENERATION_MASTER.md with these specifications:

Project: Recipe Collection Website API

Data Models:
- User: email, username, password, profile_image
- Recipe: title, description, ingredients (array), instructions (array),
  prep_time, cook_time, servings, difficulty, category, tags,
  image_url, is_public, created_by, created_at, updated_at
- Category: name, description
- Favorite: user_id, recipe_id, created_at

API Endpoints:

Public:
- POST /api/v1/auth/register - User registration
- POST /api/v1/auth/login - User login
- GET /api/v1/recipes/public - List public recipes with pagination
- GET /api/v1/recipes/public/:id - Get single public recipe
- GET /api/v1/categories - List all categories

Protected (Requires Authentication):
- POST /api/v1/recipes - Create new recipe
- PUT /api/v1/recipes/:id - Update own recipe
- DELETE /api/v1/recipes/:id - Delete own recipe
- GET /api/v1/recipes/my - Get user's recipes
- POST /api/v1/recipes/:id/favorite - Add to favorites
- DELETE /api/v1/recipes/:id/favorite - Remove from favorites
- GET /api/v1/recipes/favorites - Get user's favorites
- GET /api/v1/profile - Get user profile
- PUT /api/v1/profile - Update user profile

Admin (Requires Admin Permission):
- GET /api/v1/admin/recipes - List all recipes
- DELETE /api/v1/admin/recipes/:id - Delete any recipe
- POST /api/v1/categories - Create category
- PUT /api/v1/categories/:id - Update category
- DELETE /api/v1/categories/:id - Delete category

Features:
- Input validation (sanitize ingredients, instructions)
- Recipe ownership verification
- Search by title, ingredients, category
- Pagination on all list endpoints
- Image URL validation
- Audit logging for recipe creation/deletion

Follow all standards from ai-templates:
- Logging: who/what/why/where on every log
- Security: input validation, auth middleware
- Error handling: never expose internal errors
- Testing: minimum 80% coverage
```

### Step 5: Review Generated Code

Claude Code will generate:

```
recipe-api/
├── cmd/lambda/main.go
├── internal/
│   ├── api/
│   │   ├── handlers/
│   │   │   ├── auth.go
│   │   │   ├── recipe.go
│   │   │   ├── category.go
│   │   │   └── profile.go
│   │   ├── middleware/
│   │   └── routes/
│   ├── database/
│   │   ├── models/
│   │   │   ├── user.go
│   │   │   ├── recipe.go
│   │   │   └── category.go
│   │   └── repository/
│   └── service/
├── deployments/
│   └── template.yaml
└── .github/workflows/deploy.yml
```

**Check:**
- [ ] All logs have who/what/why/where
- [ ] Input validation on all endpoints
- [ ] Error handling doesn't expose internals
- [ ] Tests included
- [ ] SAM template has all DynamoDB tables

### Step 6: Configure Environment

```bash
cd recipe-api

# Copy environment template
cp ../ai-templates/config/.env.example .env

# Edit configuration
nano .env
```

Update `.env`:
```bash
SERVICE_NAME=recipe-api
ENVIRONMENT=dev
AWS_REGION=us-east-1

USERS_TABLE=dev-users
SESSIONS_TABLE=dev-sessions
RECIPES_TABLE=dev-recipes
CATEGORIES_TABLE=dev-categories
FAVORITES_TABLE=dev-favorites

JWT_SECRET=your-generated-secret-here
COOKIE_SECURE=false  # true in production
```

Generate secrets:
```bash
# Generate JWT secret
openssl rand -base64 32

# Generate encryption key
openssl rand -hex 32
```

### Step 7: Test Locally (Optional)

```bash
# Install dependencies
go mod download

# Run tests
make test

# Run locally with SAM
make run-local
```

### Step 8: Deploy to AWS

```bash
# Configure AWS credentials
aws configure

# Create S3 bucket for SAM artifacts (one-time)
aws s3 mb s3://recipe-api-sam-artifacts

# Deploy to dev
make deploy-dev

# Get API endpoint
aws cloudformation describe-stacks \
  --stack-name recipe-api-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
  --output text
```

### Step 9: Test the Deployed API

```bash
# Get API URL
API_URL=$(aws cloudformation describe-stacks \
  --stack-name recipe-api-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
  --output text)

# Test health check
curl $API_URL/health

# Register user
curl -X POST $API_URL/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "chef@example.com",
    "username": "masterchef",
    "password": "SecurePass123!",
    "name": "Master Chef"
  }'

# Login
curl -X POST $API_URL/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "chef@example.com",
    "password": "SecurePass123!"
  }' \
  -c cookies.txt

# Create recipe (authenticated)
curl -X POST $API_URL/api/v1/recipes \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "title": "Classic Chocolate Chip Cookies",
    "description": "Delicious homemade cookies",
    "ingredients": [
      "2 cups all-purpose flour",
      "1 tsp baking soda",
      "1 cup butter, softened",
      "3/4 cup sugar",
      "2 eggs",
      "2 cups chocolate chips"
    ],
    "instructions": [
      "Preheat oven to 375°F",
      "Mix dry ingredients",
      "Cream butter and sugar",
      "Add eggs and mix well",
      "Combine wet and dry ingredients",
      "Fold in chocolate chips",
      "Bake for 10-12 minutes"
    ],
    "prep_time": 15,
    "cook_time": 12,
    "servings": 24,
    "difficulty": "easy",
    "category": "desserts",
    "is_public": true
  }'
```

---

## Recipe Website Example

### Complete Requirements Document

See: [examples/RECIPE_WEBSITE_REQUIREMENTS.md](./examples/RECIPE_WEBSITE_REQUIREMENTS.md)

### Data Models

#### Recipe Model
```go
type Recipe struct {
    RecipeID     string    `dynamodbav:"recipe_id"`     // PK
    Title        string    `dynamodbav:"title"`
    Description  string    `dynamodbav:"description"`
    Ingredients  []string  `dynamodbav:"ingredients"`
    Instructions []string  `dynamodbav:"instructions"`
    PrepTime     int       `dynamodbav:"prep_time"`     // minutes
    CookTime     int       `dynamodbav:"cook_time"`     // minutes
    Servings     int       `dynamodbav:"servings"`
    Difficulty   string    `dynamodbav:"difficulty"`    // easy, medium, hard
    Category     string    `dynamodbav:"category"`
    Tags         []string  `dynamodbav:"tags"`
    ImageURL     string    `dynamodbav:"image_url"`
    IsPublic     bool      `dynamodbav:"is_public"`
    CreatedBy    string    `dynamodbav:"created_by"`    // GSI
    CreatedAt    time.Time `dynamodbav:"created_at"`
    UpdatedAt    time.Time `dynamodbav:"updated_at"`
}
```

#### DynamoDB Tables

**Recipes Table:**
```yaml
RecipesTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: !Sub ${Environment}-recipes
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: recipe_id
        AttributeType: S
      - AttributeName: created_by
        AttributeType: S
      - AttributeName: category
        AttributeType: S
    KeySchema:
      - AttributeName: recipe_id
        KeyType: HASH
    GlobalSecondaryIndexes:
      - IndexName: CreatedByIndex
        KeySchema:
          - AttributeName: created_by
            KeyType: HASH
        Projection:
          ProjectionType: ALL
      - IndexName: CategoryIndex
        KeySchema:
          - AttributeName: category
            KeyType: HASH
        Projection:
          ProjectionType: ALL
```

### Example Logging

Every operation must include who/what/why/where:

```go
// Creating a recipe
Logger.Info().
    Str("who", fmt.Sprintf("user:%s", user.Email)).
    Str("what", "created recipe").
    Str("why", "user submitted new recipe via API").
    Str("where", "handlers:create-recipe").
    Str("recipe_id", recipe.RecipeID).
    Str("recipe_title", recipe.Title).
    Msg("Recipe created successfully")

// Searching recipes
Logger.Debug().
    Str("who", "anonymous").
    Str("what", "searched public recipes").
    Str("why", "user searched for recipes by ingredient").
    Str("where", "handlers:search-recipes").
    Str("search_term", searchTerm).
    Int("results_count", len(results)).
    Msg("Recipe search completed")

// Deleting recipe
Logger.Info().
    Str("who", fmt.Sprintf("user:%s", user.Email)).
    Str("what", "deleted recipe").
    Str("why", "user requested recipe deletion").
    Str("where", "handlers:delete-recipe").
    Str("recipe_id", recipeID).
    Msg("Recipe deleted successfully")
```

---

## Using Automation Scripts

### Available Scripts

All scripts are in the `scripts/` directory:

1. **bootstrap-project.sh** - Create new project from template
2. **generate-prompt.sh** - Generate Claude Code prompt
3. **setup-aws.sh** - Configure AWS resources
4. **deploy-helper.sh** - Simplified deployment
5. **test-api.sh** - Test deployed API endpoints

### Script: bootstrap-project.sh

Creates a new project with standard structure:

```bash
./scripts/bootstrap-project.sh <project-name>
```

**Example:**
```bash
./scripts/bootstrap-project.sh recipe-api
```

**What it does:**
1. Creates project directory
2. Initializes Go module
3. Copies configuration templates
4. Creates directory structure
5. Generates initial prompt file

**Output:**
```
recipe-api/
├── .env.example
├── .gitignore
├── go.mod
├── .claude-prompt.txt
└── README.md
```

### Script: generate-prompt.sh

Generates a customized Claude Code prompt:

```bash
./scripts/generate-prompt.sh <project-name> [options]
```

**Example:**
```bash
./scripts/generate-prompt.sh recipe-api \
  --auth \
  --crud recipes \
  --crud categories \
  --search \
  --favorites
```

**Options:**
- `--auth` - Include authentication
- `--crud <model>` - Add CRUD endpoints for model
- `--search` - Include search functionality
- `--admin` - Include admin endpoints
- `--favorites` - Include favorites feature
- `--upload` - Include file upload

**Output:**
Generates `.claude-prompt.txt` with complete specifications

### Script: setup-aws.sh

Sets up AWS resources:

```bash
./scripts/setup-aws.sh <project-name> <environment>
```

**Example:**
```bash
./scripts/setup-aws.sh recipe-api dev
```

**What it does:**
1. Creates S3 bucket for SAM artifacts
2. Sets up CloudWatch log groups
3. Creates IAM roles (if needed)
4. Configures secrets in Secrets Manager

### Script: deploy-helper.sh

Simplified deployment:

```bash
./scripts/deploy-helper.sh <project-dir> <environment>
```

**Example:**
```bash
./scripts/deploy-helper.sh ../recipe-api dev
```

**What it does:**
1. Runs tests
2. Builds Lambda binary
3. Packages with SAM
4. Deploys to AWS
5. Outputs API endpoint

### Script: test-api.sh

Tests deployed API:

```bash
./scripts/test-api.sh <api-url>
```

**Example:**
```bash
./scripts/test-api.sh https://abc123.execute-api.us-east-1.amazonaws.com/Prod
```

**What it does:**
1. Tests health endpoint
2. Registers test user
3. Performs login
4. Creates test data
5. Tests all CRUD operations
6. Cleans up test data

---

## Customization Guide

### Modifying for Your Use Case

1. **Change Data Models:**
   Edit the prompt to specify your models:
   ```
   Data Models:
   - YourModel: field1, field2, field3
   ```

2. **Add/Remove Endpoints:**
   Specify exactly which endpoints you need:
   ```
   API Endpoints:
   - POST /api/v1/your-resource
   - GET /api/v1/your-resource/:id
   ```

3. **Add Business Logic:**
   Describe business rules in the prompt:
   ```
   Business Rules:
   - Users can only edit their own recipes
   - Admin can delete any recipe
   - Public recipes are searchable by anyone
   ```

4. **Customize Authentication:**
   Specify auth requirements:
   ```
   Authentication:
   - JWT tokens (instead of cookies)
   - OAuth2 integration
   - API key for service-to-service
   ```

### Extending Generated Code

After generation, you can extend:

1. **Add New Handlers:**
   ```bash
   # Create new handler following pattern
   cp internal/api/handlers/recipe.go internal/api/handlers/review.go
   # Edit and add to routes
   ```

2. **Add Middleware:**
   ```bash
   # Create new middleware
   cp internal/api/middleware/auth.go internal/api/middleware/cache.go
   ```

3. **Add Services:**
   ```bash
   # Create new service layer
   cp internal/service/recipe_service.go internal/service/email_service.go
   ```

---

## Troubleshooting

### Issue: Claude Code doesn't follow logging standards

**Solution:**
Be explicit in the prompt:
```
CRITICAL: Every log MUST include these four fields:
- who: Actor (e.g., "user:email@example.com")
- what: Action in past tense (e.g., "created recipe")
- why: Business reason in ONE sentence (e.g., "user submitted new recipe")
- where: Component (e.g., "handlers:create-recipe")

Example:
Logger.Info().
    Str("who", "user:john@example.com").
    Str("what", "created recipe").
    Str("why", "user submitted new recipe via API").
    Str("where", "handlers:create-recipe").
    Msg("Recipe created")
```

### Issue: Generated code missing error handling

**Solution:**
Add to prompt:
```
Error Handling Requirements:
- Wrap all operations in error handling
- Never expose internal errors to clients
- Log all errors with who/what/why/where
- Return appropriate HTTP status codes
```

### Issue: DynamoDB tables not created

**Solution:**
Check SAM template includes all tables:
```yaml
Resources:
  RecipesTable:
    Type: AWS::DynamoDB::Table
    # ...
```

### Issue: Deployment fails

**Common causes:**
1. AWS credentials not configured
2. S3 bucket doesn't exist
3. IAM permissions insufficient

**Solutions:**
```bash
# Check AWS credentials
aws sts get-caller-identity

# Create S3 bucket
aws s3 mb s3://your-sam-bucket

# Check IAM permissions
aws iam get-user
```

### Issue: Tests failing

**Solution:**
Review test output and ensure:
- Mock implementations included
- Test data follows validation rules
- All required fields populated

---

## Next Steps

1. ✅ Generate your application
2. ✅ Review generated code
3. ✅ Configure environment
4. ✅ Deploy to dev
5. ✅ Test API endpoints
6. ✅ Add custom business logic
7. ✅ Deploy to staging
8. ✅ Production deployment

---

## Additional Resources

- **[GENERATION_MASTER.md](./GENERATION_MASTER.md)** - Complete generation guide
- **[standards/](./standards/)** - Detailed technical standards
- **[reference/](./reference/)** - Quick reference cards
- **[guides/](./guides/)** - Implementation guides

---

## Example Project Timeline

| Phase | Time | Activities |
|-------|------|------------|
| Planning | 1 hour | Define requirements, data models |
| Generation | 30 min | Generate with Claude Code |
| Review | 1 hour | Review code, check standards |
| Configuration | 30 min | Set up AWS, configure environment |
| Testing | 1 hour | Local testing, fix issues |
| Deployment | 30 min | Deploy to dev, test |
| **Total** | **4.5 hours** | **Working MVP** |

---

**Version:** 1.0
**Last Updated:** November 19, 2025
**Maintained By:** DevOps/SRE Team
