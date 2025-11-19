# AWS Lambda Go/Fiber Templates

Production-ready templates for building AWS Lambda applications with Go and Fiber framework following Ally Financial SRE/DevSecOps standards.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-FF9900?style=flat&logo=amazon-aws)](https://aws.amazon.com/lambda/)
[![Fiber](https://img.shields.io/badge/Fiber-v2-00ACD7?style=flat)](https://gofiber.io/)

---

## 🤖 For Claude Code CLI (Start Here!)

**Entry Point:** [GENERATION_MASTER.md](./GENERATION_MASTER.md)

This file contains everything Claude Code needs to generate applications following our standards.

```bash
# Generate new application
claude code "Create a Lambda API following ai-templates/GENERATION_MASTER.md"

# Add specific feature
claude code "Implement API key auth per ai-templates security standards"

# Fix logging
claude code "Fix logging to match ai-templates/reference/LOGGING_QUICK_REFERENCE.md"
```

---

## 👨‍💻 For Developers (Humans)

### Quick Start

| I want to... | Go here |
|--------------|---------|
| Generate an app with Claude | [GENERATION_MASTER.md](./GENERATION_MASTER.md) |
| Get a quick reference | [reference/](./reference/) |
| See working examples | [examples/](./examples/) (coming soon) |
| Understand the architecture | [standards/ARCHITECTURE_STANDARDS.md](./standards/ARCHITECTURE_STANDARDS.md) |
| Learn logging patterns | [standards/LOGGING_STANDARDS.md](./standards/LOGGING_STANDARDS.md) |
| Implement security features | [guides/SECURITY_IMPLEMENTATION.md](./guides/SECURITY_IMPLEMENTATION.md) |

---

## 📁 Repository Structure

```
ai-templates/
│
├── 🤖 GENERATION_MASTER.md              ← Claude Code starts here (18KB)
├── 📄 README.md                          ← You are here
├── 📋 PROJECT_STANDARDS.md               ← Complete reference (90KB)
├── 📝 CLAUDE_CODE_PROMPT.md              ← User-facing generation template
│
├── 📁 standards/                         ← Detailed specifications
│   ├── ARCHITECTURE_STANDARDS.md         │ Project structure, Lambda patterns
│   ├── CODING_STANDARDS.md               │ Go/Fiber patterns, testing
│   ├── SECURITY_STANDARDS.md             │ Auth, sessions, permissions
│   ├── DATABASE_STANDARDS.md             │ DynamoDB patterns
│   ├── DEPLOYMENT_STANDARDS.md           │ SAM, GitHub Actions
│   └── LOGGING_STANDARDS.md              │ Observability requirements
│
├── 📁 templates/                         ← Reusable code templates
│   └── (coming soon)
│
├── 📁 examples/                          ← Working examples
│   └── (coming soon)
│
├── 📁 guides/                            ← How-to guides
│   └── SECURITY_IMPLEMENTATION.md        │ Security features guide
│
├── 📁 reference/                         ← Quick reference cards
│   └── LOGGING_QUICK_REFERENCE.md        │ One-page logging guide
│
└── 📁 config/                            ← Configuration files
    ├── .env.example                      │ Environment variables
    └── .gitignore                        │ Git ignore patterns
```

---

## 🎯 What's Included

### ✅ Architecture Patterns
- AWS Lambda with API Gateway
- GoFiber v2 framework integration
- DynamoDB for state management
- CloudWatch structured logging

### ✅ Authentication & Security
- Cookie-based sessions with DynamoDB
- bcrypt password hashing (cost 14)
- Role-based access control (RBAC)
- API key management system
- Input validation framework
- Security headers middleware

### ✅ Observability
- **Human-readable logging** (who/what/why/where pattern)
- CloudWatch Insights query patterns
- Request tracing
- Performance monitoring

### ✅ Deployment & CI/CD
- AWS SAM templates
- GitHub Actions workflows
- Multi-environment support (dev, staging, prod)
- Automated testing and security scanning

### ✅ Security Features
- Account lockout & suspicious activity detection
- TLS 1.3 enforcement
- Comprehensive input validation
- Audit logging
- Secrets scanning
- Password breach checking (HaveIBeenPwned)

---

## 🚀 Quick Start Guide

### For New Projects

1. **Review the generation master:**
   ```bash
   cat GENERATION_MASTER.md
   ```

2. **Use Claude Code to generate:**
   ```bash
   claude code "Generate a Lambda API following GENERATION_MASTER.md with user auth"
   ```

3. **Configure environment:**
   ```bash
   cp config/.env.example .env
   # Edit .env with your values
   ```

4. **Deploy:**
   ```bash
   make deploy-dev
   ```

### For Existing Projects

1. **Review current standards:**
   - Architecture: [standards/ARCHITECTURE_STANDARDS.md](./standards/ARCHITECTURE_STANDARDS.md)
   - Logging: [standards/LOGGING_STANDARDS.md](./standards/LOGGING_STANDARDS.md)

2. **Add missing features:**
   ```bash
   claude code "Add API key auth following guides/SECURITY_IMPLEMENTATION.md"
   ```

3. **Fix logging:**
   ```bash
   claude code "Update all logs to match reference/LOGGING_QUICK_REFERENCE.md"
   ```

---

## 📚 Documentation Index

### Essential Documents (Read These First)

| Document | Purpose | Size | Audience |
|----------|---------|------|----------|
| **[GENERATION_MASTER.md](./GENERATION_MASTER.md)** | Claude Code entry point | 18KB | AI/Claude |
| **[README.md](./README.md)** | This file - navigation hub | 5KB | Everyone |
| **[reference/LOGGING_QUICK_REFERENCE.md](./reference/LOGGING_QUICK_REFERENCE.md)** | One-page logging guide | 5KB | Developers |

### Detailed Standards

| Standard | Description | Link |
|----------|-------------|------|
| Architecture | Project structure, Lambda patterns | [standards/ARCHITECTURE_STANDARDS.md](./standards/ARCHITECTURE_STANDARDS.md) |
| Coding | Go/Fiber patterns, testing | [standards/CODING_STANDARDS.md](./standards/CODING_STANDARDS.md) |
| Security | Auth, sessions, permissions | [standards/SECURITY_STANDARDS.md](./standards/SECURITY_STANDARDS.md) |
| Logging | Observability (who/what/why/where) | [standards/LOGGING_STANDARDS.md](./standards/LOGGING_STANDARDS.md) |
| Database | DynamoDB patterns | [standards/DATABASE_STANDARDS.md](./standards/DATABASE_STANDARDS.md) |
| Deployment | SAM, GitHub Actions | [standards/DEPLOYMENT_STANDARDS.md](./standards/DEPLOYMENT_STANDARDS.md) |

### Implementation Guides

| Guide | Description | Link |
|-------|-------------|------|
| Security Implementation | Complete security features guide | [guides/SECURITY_IMPLEMENTATION.md](./guides/SECURITY_IMPLEMENTATION.md) |

### Complete Reference

| Document | Description | Size | When to Use |
|----------|-------------|------|-------------|
| **[PROJECT_STANDARDS.md](./PROJECT_STANDARDS.md)** | Comprehensive reference | 90KB | Deep dive, complete context |
| **[CLAUDE_CODE_PROMPT.md](./CLAUDE_CODE_PROMPT.md)** | User generation template | 12KB | Manual generation requests |

---

## 🔑 Key Concepts

### The Logging Pattern (Most Important!)

**Every log MUST include four human-readable fields:**

```go
Logger.Info().
    Str("who", "user:john@example.com").      // Actor (max 50 chars)
    Str("what", "created user account").      // Action in past tense (max 60 chars)
    Str("why", "user registration completed"). // Business reason, ONE sentence (max 100 chars)
    Str("where", "auth-service:register").    // Component (max 50 chars)
    Msg("User registered successfully")
```

**Why this matters:**
- Instant understanding without reading code
- Powerful CloudWatch queries
- Faster incident response
- Better compliance and auditing

→ See: [standards/LOGGING_STANDARDS.md](./standards/LOGGING_STANDARDS.md)

---

## 🛠️ Common Tasks

### Generate New Application
```bash
claude code "Create a new Lambda API following ai-templates with:
- User authentication (email/password)
- Session management in DynamoDB
- Admin endpoints with RBAC
- Health check endpoint"
```

### Add Security Features
```bash
claude code "Add these security features following ai-templates:
- Account lockout after 5 failed attempts
- API key authentication for service-to-service
- Input validation on all endpoints"
```

### Fix Logging
```bash
claude code "Review all logs in src/ and fix to match
ai-templates/reference/LOGGING_QUICK_REFERENCE.md requirements
(who/what/why/where pattern)"
```

### Add Tests
```bash
claude code "Generate unit tests for handlers/ following
ai-templates/standards/CODING_STANDARDS.md testing patterns
(minimum 80% coverage)"
```

---

## ✅ Quality Checklist

Before considering code complete:

### Structure & Organization
- [ ] Follows project structure from [ARCHITECTURE_STANDARDS.md](./standards/ARCHITECTURE_STANDARDS.md)
- [ ] All files in correct directories
- [ ] Proper package naming

### Logging (Critical!)
- [ ] Every log has who/what/why/where
- [ ] `why` field explains business reason (not technical)
- [ ] `why` field is max 100 characters, one sentence
- [ ] No sensitive data logged (passwords, tokens, keys)

### Security
- [ ] Input validation on all endpoints
- [ ] Error messages don't leak internals
- [ ] No secrets in code
- [ ] Security headers configured
- [ ] CORS properly configured

### Code Quality
- [ ] Tests included (80%+ coverage)
- [ ] Error handling on all operations
- [ ] Context propagated through calls
- [ ] Proper HTTP status codes

### Lambda Specific
- [ ] Heavy initialization in init()
- [ ] DynamoDB client reused (not recreated)
- [ ] No local file operations
- [ ] Timeout configured (30s)

---

## 🤝 Contributing

To update these templates:

1. Make changes to appropriate standard file
2. Update GENERATION_MASTER.md if changes affect code generation
3. Update cross-references if adding new files
4. Test with Claude Code CLI
5. Update version numbers

---

## 📖 Additional Resources

- **AWS Lambda Go:** https://github.com/aws/aws-lambda-go
- **Fiber Framework:** https://gofiber.io/
- **DynamoDB Best Practices:** https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices.html
- **Ally Financial DevSecOps:** Internal wiki

---

## 📞 Support

- **Issues:** Report in repository issues
- **Questions:** Ask in #lambda-go-support Slack channel
- **SRE Team:** 24x7 on-call support

---

## 📝 License

Internal use only - Ally Financial Inc.

---

**Version:** 1.0
**Last Updated:** November 19, 2025
**Maintained By:** DevOps/SRE Team
