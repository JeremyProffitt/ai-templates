# Recipe Website Example - Complete Implementation Guide

**Use Case:** Recipe collection and editing website
**Generated with:** ai-templates
**Time to MVP:** ~4 hours

---

## Overview

This example demonstrates how to use ai-templates to generate a complete recipe collection website with user authentication, CRUD operations, search, and favorites functionality.

### Features

- ✅ User registration and authentication
- ✅ Create, read, update, delete recipes
- ✅ Recipe categories and tags
- ✅ Search recipes by title, ingredients, or category
- ✅ Favorite recipes
- ✅ Public/private recipe visibility
- ✅ User profiles
- ✅ Admin dashboard

---

## Quick Start

### Using Automation Script

```bash
cd ai-templates

# Generate the prompt
./scripts/generate-prompt.sh recipe-api \
    --auth \
    --crud recipes \
    --crud categories \
    --search \
    --favorites \
    --description "Recipe collection and editing website" \
    > recipe-prompt.txt

# Generate with Claude Code
claude code "$(cat recipe-prompt.txt)"

# Configure and deploy
cd ../recipe-api
cp ../ai-templates/config/.env.example .env
# Edit .env
make deploy-dev
```

### Manual Generation

```bash
claude code
```

Then paste the prompt from [Recipe Generation Prompt](#recipe-generation-prompt) section below.

---

## Data Models

### Recipe
```go
type Recipe struct {
    RecipeID     string    `dynamodbav:"recipe_id" json:"recipe_id"`           // PK
    Title        string    `dynamodbav:"title" json:"title" validate:"required,min=3,max=200"`
    Description  string    `dynamodbav:"description" json:"description" validate:"required,max=1000"`
    Ingredients  []string  `dynamodbav:"ingredients" json:"ingredients" validate:"required,min=1,dive,required"`
    Instructions []string  `dynamodbav:"instructions" json:"instructions" validate:"required,min=1,dive,required"`
    PrepTime     int       `dynamodbav:"prep_time" json:"prep_time" validate:"required,min=0"`          // minutes
    CookTime     int       `dynamodbav:"cook_time" json:"cook_time" validate:"required,min=0"`          // minutes
    Servings     int       `dynamodbav:"servings" json:"servings" validate:"required,min=1"`
    Difficulty   string    `dynamodbav:"difficulty" json:"difficulty" validate:"required,oneof=easy medium hard"`
    Category     string    `dynamodbav:"category" json:"category" validate:"required"`
    Tags         []string  `dynamodbav:"tags" json:"tags,omitempty"`
    ImageURL     string    `dynamodbav:"image_url" json:"image_url,omitempty" validate:"omitempty,url"`
    IsPublic     bool      `dynamodbav:"is_public" json:"is_public"`
    CreatedBy    string    `dynamodbav:"created_by" json:"created_by"`         // GSI
    CreatedAt    time.Time `dynamodbav:"created_at" json:"created_at"`
    UpdatedAt    time.Time `dynamodbav:"updated_at" json:"updated_at"`
}
```

### Category
```go
type Category struct {
    CategoryID  string    `dynamodbav:"category_id" json:"category_id"`       // PK
    Name        string    `dynamodbav:"name" json:"name" validate:"required"`
    Description string    `dynamodbav:"description" json:"description"`
    IconURL     string    `dynamodbav:"icon_url" json:"icon_url,omitempty"`
    CreatedAt   time.Time `dynamodbav:"created_at" json:"created_at"`
}
```

### Favorite
```go
type Favorite struct {
    UserID    string    `dynamodbav:"user_id" json:"user_id"`       // PK
    RecipeID  string    `dynamodbav:"recipe_id" json:"recipe_id"`   // SK
    CreatedAt time.Time `dynamodbav:"created_at" json:"created_at"`
}
```

---

## API Endpoints

### Authentication
```
POST   /api/v1/auth/register       - Register new user
POST   /api/v1/auth/login          - User login
POST   /api/v1/auth/logout         - User logout
GET    /health                     - Health check
```

### Recipes (Public)
```
GET    /api/v1/recipes/public      - List all public recipes (paginated)
GET    /api/v1/recipes/public/:id  - Get single public recipe
GET    /api/v1/recipes/search      - Search public recipes
```

### Recipes (Protected)
```
GET    /api/v1/recipes/my          - Get user's recipes
POST   /api/v1/recipes             - Create new recipe
GET    /api/v1/recipes/:id         - Get recipe (own or public)
PUT    /api/v1/recipes/:id         - Update own recipe
DELETE /api/v1/recipes/:id         - Delete own recipe
```

### Favorites (Protected)
```
GET    /api/v1/recipes/favorites       - Get user's favorite recipes
POST   /api/v1/recipes/:id/favorite    - Add recipe to favorites
DELETE /api/v1/recipes/:id/favorite    - Remove recipe from favorites
```

### Categories
```
GET    /api/v1/categories          - List all categories
GET    /api/v1/categories/:id      - Get category with recipes
```

### Admin (Protected + Admin Role)
```
GET    /api/v1/admin/recipes       - List all recipes
DELETE /api/v1/admin/recipes/:id   - Delete any recipe
POST   /api/v1/categories          - Create category
PUT    /api/v1/categories/:id      - Update category
DELETE /api/v1/categories/:id      - Delete category
GET    /api/v1/admin/users         - List all users
GET    /api/v1/admin/stats         - System statistics
```

---

## Example API Usage

### 1. Register a User

```bash
curl -X POST https://your-api.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "chef@example.com",
    "username": "masterchef",
    "password": "SecurePass123!",
    "name": "Master Chef"
  }'
```

Response:
```json
{
  "user_id": "usr_abc123",
  "message": "User registered successfully"
}
```

### 2. Login

```bash
curl -X POST https://your-api.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "chef@example.com",
    "password": "SecurePass123!"
  }'
```

### 3. Create a Recipe

```bash
curl -X POST https://your-api.com/api/v1/recipes \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "title": "Classic Chocolate Chip Cookies",
    "description": "The best chocolate chip cookies you will ever make!",
    "ingredients": [
      "2 cups all-purpose flour",
      "1 tsp baking soda",
      "1/2 tsp salt",
      "1 cup butter, softened",
      "3/4 cup granulated sugar",
      "3/4 cup brown sugar",
      "2 large eggs",
      "2 tsp vanilla extract",
      "2 cups chocolate chips"
    ],
    "instructions": [
      "Preheat oven to 375°F (190°C)",
      "Mix flour, baking soda, and salt in a bowl",
      "In a large bowl, cream butter and sugars until fluffy",
      "Beat in eggs and vanilla",
      "Gradually blend in flour mixture",
      "Stir in chocolate chips",
      "Drop rounded tablespoons onto ungreased cookie sheets",
      "Bake for 9-11 minutes or until golden brown",
      "Cool on baking sheet for 2 minutes, then transfer to wire rack"
    ],
    "prep_time": 15,
    "cook_time": 11,
    "servings": 48,
    "difficulty": "easy",
    "category": "desserts",
    "tags": ["cookies", "chocolate", "baking"],
    "is_public": true
  }'
```

### 4. Search Recipes

```bash
curl "https://your-api.com/api/v1/recipes/search?q=chocolate&category=desserts"
```

### 5. Add to Favorites

```bash
curl -X POST https://your-api.com/api/v1/recipes/rec_abc123/favorite \
  -b cookies.txt
```

### 6. Get My Favorites

```bash
curl https://your-api.com/api/v1/recipes/favorites \
  -b cookies.txt
```

---

## DynamoDB Schema

### Recipes Table

```yaml
RecipesTable:
  TableName: ${Environment}-recipes
  PartitionKey: recipe_id (String)
  GlobalSecondaryIndexes:
    - CreatedByIndex:
        PartitionKey: created_by
        Projection: ALL
    - CategoryIndex:
        PartitionKey: category
        SortKey: created_at
        Projection: ALL
```

### Categories Table

```yaml
CategoriesTable:
  TableName: ${Environment}-categories
  PartitionKey: category_id (String)
```

### Favorites Table

```yaml
FavoritesTable:
  TableName: ${Environment}-favorites
  PartitionKey: user_id (String)
  SortKey: recipe_id (String)
  GlobalSecondaryIndexes:
    - RecipeIndex:
        PartitionKey: recipe_id
        Projection: ALL
```

---

## Logging Examples

### Creating a Recipe

```go
Logger.Info().
    Str("who", fmt.Sprintf("user:%s", user.Email)).
    Str("what", "created recipe").
    Str("why", "user submitted new recipe via API").
    Str("where", "handlers:create-recipe").
    Str("recipe_id", recipe.RecipeID).
    Str("recipe_title", recipe.Title).
    Bool("is_public", recipe.IsPublic).
    Msg("Recipe created successfully")
```

### Searching Recipes

```go
Logger.Debug().
    Str("who", "anonymous").
    Str("what", "searched public recipes").
    Str("why", "user searched for recipes by keyword").
    Str("where", "handlers:search-recipes").
    Str("search_term", searchTerm).
    Str("category", category).
    Int("results_count", len(results)).
    Msg("Recipe search completed")
```

### Adding to Favorites

```go
Logger.Info().
    Str("who", fmt.Sprintf("user:%s", user.Email)).
    Str("what", "added recipe to favorites").
    Str("why", "user favorited recipe for later access").
    Str("where", "handlers:add-favorite").
    Str("recipe_id", recipeID).
    Msg("Recipe added to favorites")
```

---

## Recipe Generation Prompt

Use this complete prompt with Claude Code:

```
Create a complete AWS Lambda Go/Fiber application following ai-templates/GENERATION_MASTER.md

Project Name: recipe-api
Description: Recipe collection and editing website with user authentication

Architecture:
- AWS Lambda with API Gateway
- GoFiber v2 framework
- DynamoDB for all data storage
- Cookie-based sessions
- Structured logging (who/what/why/where pattern)

Data Models:
- User: user_id (PK), email, username, password_hash, name, profile_image_url, created_at, updated_at, is_active
- Recipe: recipe_id (PK), title, description, ingredients (array), instructions (array), prep_time, cook_time, servings, difficulty, category, tags (array), image_url, is_public, created_by (GSI), created_at, updated_at
- Category: category_id (PK), name, description, icon_url, created_at
- Favorite: user_id (PK), recipe_id (SK), created_at

API Endpoints:

Public Endpoints:
- GET /health - Health check
- POST /api/v1/auth/register - User registration
- POST /api/v1/auth/login - User login
- POST /api/v1/auth/logout - User logout
- GET /api/v1/recipes/public - List public recipes (paginated)
- GET /api/v1/recipes/public/:id - Get single public recipe
- GET /api/v1/recipes/search - Search public recipes by title, ingredients, category
- GET /api/v1/categories - List all categories

Protected Endpoints (Authentication Required):
- GET /api/v1/recipes/my - Get user's recipes
- POST /api/v1/recipes - Create new recipe
- GET /api/v1/recipes/:id - Get recipe (own or public)
- PUT /api/v1/recipes/:id - Update own recipe (verify ownership)
- DELETE /api/v1/recipes/:id - Delete own recipe (verify ownership)
- POST /api/v1/recipes/:id/favorite - Add to favorites
- DELETE /api/v1/recipes/:id/favorite - Remove from favorites
- GET /api/v1/recipes/favorites - Get user's favorite recipes
- GET /api/v1/profile - Get user profile
- PUT /api/v1/profile - Update user profile

Admin Endpoints (Admin Permission Required):
- GET /api/v1/admin/recipes - List all recipes
- DELETE /api/v1/admin/recipes/:id - Delete any recipe
- POST /api/v1/categories - Create category
- PUT /api/v1/categories/:id - Update category
- DELETE /api/v1/categories/:id - Delete category
- GET /api/v1/admin/users - List all users
- GET /api/v1/admin/stats - System statistics

Business Rules:
- Users can only edit/delete their own recipes
- Admins can delete any recipe
- Public recipes are searchable by everyone
- Private recipes are only visible to the owner
- Recipe ingredients and instructions are arrays (min 1 item each)
- Categories are predefined by admins
- Favorites are user-specific

Required Features:
- Input validation (sanitize ingredients/instructions arrays, validate URLs, check required fields)
- Recipe ownership verification on update/delete
- Search functionality (title, ingredients, category)
- Pagination on all list endpoints (default page=1, limit=20)
- Error handling that never exposes internal details
- CORS configuration
- Security headers middleware
- Rate limiting on auth endpoints

CRITICAL - LOGGING PATTERN:
Every log MUST include these four fields:
- who: Actor (e.g., "user:chef@example.com", "system:search-indexer")
- what: Action in past tense (e.g., "created recipe", "searched recipes")
- why: Business reason in ONE sentence (e.g., "user submitted new recipe via API")
- where: Component (e.g., "handlers:create-recipe", "service:recipe-search")

Example:
Logger.Info().
    Str("who", "user:chef@example.com").
    Str("what", "created recipe").
    Str("why", "user submitted new recipe via API").
    Str("where", "handlers:create-recipe").
    Str("recipe_id", recipe.RecipeID).
    Msg("Recipe created successfully")

DynamoDB Tables:
- users (PK: user_id, GSI: email, GSI: username)
- sessions (PK: session_id, GSI: user_id, TTL: expires_at)
- recipes (PK: recipe_id, GSI: created_by, GSI: category)
- categories (PK: category_id)
- favorites (PK: user_id, SK: recipe_id, GSI: recipe_id)

Testing Requirements:
- Unit tests for all business logic
- Integration tests for API endpoints
- Test recipe creation, search, favorites
- Minimum 80% code coverage

Follow all standards from ai-templates:
- Architecture: ai-templates/standards/ARCHITECTURE_STANDARDS.md
- Logging: ai-templates/standards/LOGGING_STANDARDS.md (CRITICAL!)
- Security: ai-templates/standards/SECURITY_STANDARDS.md
- Coding: ai-templates/standards/CODING_STANDARDS.md

Deliverables:
1. Complete Go application with all handlers
2. DynamoDB repositories for all models
3. Service layer with recipe search logic
4. Middleware for auth and security
5. Unit and integration tests
6. SAM template with all resources
7. Makefile
8. README with API documentation
```

---

## Testing the Generated API

Use the provided test script:

```bash
cd ai-templates
./scripts/test-api.sh https://your-api-url.com/Prod
```

Or test manually:

```bash
# See USAGE.md for complete testing guide
```

---

## Extending the Example

### Add Recipe Ratings

1. Add to prompt:
   ```
   - Rating: user_id (PK), recipe_id (SK), rating (1-5), comment, created_at
   - POST /api/v1/recipes/:id/rating - Add rating
   - GET /api/v1/recipes/:id/ratings - Get all ratings
   ```

2. Update Recipe model:
   ```go
   AverageRating float64 `dynamodbav:"average_rating"`
   RatingCount   int     `dynamodbav:"rating_count"`
   ```

### Add Recipe Images

1. Add S3 bucket to SAM template
2. Add image upload endpoint
3. Generate presigned URLs for uploads
4. Store URLs in recipe.ImageURL

### Add Recipe Collections

1. Add Collection model
2. Add many-to-many relationship
3. Add collection CRUD endpoints

---

## Deployment

```bash
cd recipe-api

# Deploy to dev
make deploy-dev

# Get API URL
aws cloudformation describe-stacks \
  --stack-name recipe-api-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
  --output text

# Test
../ai-templates/scripts/test-api.sh <api-url>

# Deploy to production
make deploy-prod
```

---

## Resources

- **Complete Prompt**: See above
- **API Documentation**: Generated in recipe-api/README.md
- **Standards**: [ai-templates/standards/](../standards/)
- **More Examples**: Coming soon

---

**Estimated Time:** 4-6 hours from prompt to deployed MVP
**Lines of Code:** ~3,000-4,000 (generated by Claude Code)
**AWS Cost:** ~$5-10/month for dev environment
