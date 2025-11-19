# Logging Quick Reference Card

**Print this page and keep it visible during development!**

---

## The Four Required Fields (Every Log Must Have These)

```
┌─────────────────────────────────────────────────────────────────┐
│  WHO   │ Actor/Subject     │ Max 50 chars │ user:email@...     │
│  WHAT  │ Action (past)     │ Max 60 chars │ created user       │
│  WHY   │ Business reason   │ Max 100 chars│ registration done  │
│  WHERE │ System/Component  │ Max 50 chars │ auth-service:login │
└─────────────────────────────────────────────────────────────────┘
```

---

## Copy-Paste Template

```go
Logger.Info().
    Str("who", "___________").      // user:john@example.com, system:scheduler
    Str("what", "___________").     // created user account, validated session
    Str("why", "___________").      // user registration completed successfully
    Str("where", "___________").    // auth-service:login-handler
    Msg("Human readable message")
```

---

## Field Format Rules

### WHO - Actor/Subject
**Format:** `{type}:{identifier}`

✅ Good Examples:
- `user:john@example.com`
- `system:scheduler`
- `apikey:prod_key_789`
- `service:payment-api`
- `anonymous`

❌ Bad Examples:
- `John` (no type prefix)
- `usr123` (not readable)
- `U` (cryptic)

---

### WHAT - Action Performed
**Format:** `{verb} {object}` (past tense)

✅ Good Examples:
- `created user account`
- `updated user profile`
- `deleted API key`
- `validated session token`
- `sent password reset email`

❌ Bad Examples:
- `create user` (not past tense)
- `user_create` (not readable)
- `CRUD_OP` (cryptic)

---

### WHY - Business/Technical Reason (MOST IMPORTANT!)
**Format:** ONE sentence, business-focused

✅ Good Examples:
- `user registration completed successfully`
- `session expired after 24 hours`
- `admin requested user data export`
- `detected 5 failed login attempts`
- `scheduled daily backup job`

❌ Bad Examples:
- `function returned` (too technical)
- `CreateUser() called` (implementation detail)
- `because we need to` (not a reason)
- `The user clicked submit and the form was validated and the data was written to the database` (too long!)

**Key Rule:** Answer "Why did this happen from a business perspective?"

---

### WHERE - System/Component
**Format:** `{service}:{component}`

✅ Good Examples:
- `auth-service:login-handler`
- `database:dynamodb-users`
- `external:payment-gateway`
- `job:session-cleanup`
- `middleware:session-validator`

❌ Bad Examples:
- `handler` (too vague)
- `auth` (missing component)
- `func123` (not descriptive)

---

## Common Patterns

### User Action
```go
Logger.Info().
    Str("who", "user:john@example.com").
    Str("what", "updated profile picture").
    Str("why", "user uploaded new avatar image").
    Str("where", "user-service:profile-handler").
    Msg("Profile picture updated")
```

### System Action
```go
Logger.Debug().
    Str("who", "system:user-repository").
    Str("what", "queried users table").
    Str("why", "authentication check in progress").
    Str("where", "database:dynamodb-users").
    Dur("duration_ms", duration).
    Msg("DynamoDB query completed")
```

### Error
```go
Logger.Error().
    Str("who", "system:payment-processor").
    Str("what", "failed to process payment").
    Str("why", "external gateway timeout").
    Str("where", "payment-service:charge-handler").
    Err(err).
    Msg("Payment processing failed")
```

### Security Event
```go
Logger.Warn().
    Str("who", "user:suspicious@example.com").
    Str("what", "failed login attempt").
    Str("why", "incorrect password (attempt 3/5)").
    Str("where", "auth-service:login-handler").
    Str("ip", clientIP).
    Msg("Failed login - approaching lockout")
```

---

## Before You Commit - Checklist

- [ ] Every log has `who`, `what`, `why`, `where`
- [ ] `why` field is ONE sentence, max 100 characters
- [ ] `why` explains business reason, not technical implementation
- [ ] All fields are human-readable (no abbreviations like `usr`, `op`, `db`)
- [ ] Log level is appropriate (DEBUG/INFO/WARN/ERROR)
- [ ] Sensitive data NOT logged (passwords, tokens, SSN)
- [ ] Errors include `Err(err)` field
- [ ] Message can be understood without reading code

---

## Code Review Questions

**Reviewer asks:** "Can I understand this log without looking at the code?"
**Developer checks:** Who did what, why, and where?

**Reviewer asks:** "What business event happened here?"
**Developer checks:** Is the `why` field clear?

**Reviewer asks:** "Is this log helpful for debugging?"
**Developer checks:** Does it have context (request_id, user_id, etc.)?

---

## Maximum Character Limits

| Field  | Max Length | Rule                           |
|--------|-----------|--------------------------------|
| who    | 50 chars  | {type}:{identifier}            |
| what   | 60 chars  | {verb} {object} (past tense)   |
| why    | 100 chars | ONE sentence, business reason  |
| where  | 50 chars  | {service}:{component}          |

---

## When In Doubt

Ask yourself:
1. **WHO** initiated this? (user, system, service)
2. **WHAT** happened? (action in past tense)
3. **WHY** did it happen? (business reason)
4. **WHERE** in the system? (service and component)

If you can't answer all four, your log is incomplete!

---

## Full Documentation

For complete details, examples, and advanced patterns:
- **LOGGING_STANDARDS.md** - Full specification with CloudWatch queries
- **PROJECT_STANDARDS.md** - Section on Logging Standards (line 470+)
- **CLAUDE_CODE_PROMPT.md** - Logging requirements for AI generation

---

**Remember:** Logs are for humans first, machines second!

**Version:** 1.0 | **Last Updated:** November 19, 2025
