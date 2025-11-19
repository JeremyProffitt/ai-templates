# Security Standards v1.0

**Organization:** Ally Financial SRE/DevSecOps
**Last Updated:** November 19, 2025

## Session Management

See: [../PROJECT_STANDARDS.md](../PROJECT_STANDARDS.md#session-management-standards) (lines 216-262)

**Key Points:**
- Cookie-based sessions with DynamoDB storage
- 24-hour session duration with automatic expiration
- Secure, HTTPOnly, SameSite=Strict cookies
- Session validation on every request

## Authentication & Authorization

See: [../PROJECT_STANDARDS.md](../PROJECT_STANDARDS.md#authentication--authorization-standards) (lines 263-466)

**Key Points:**
- bcrypt password hashing (cost 14)
- Role-based access control (RBAC)
- Permission-based authorization
- JWT for service-to-service auth

## Security Implementation Guide

For detailed security enhancements:
- [../guides/SECURITY_IMPLEMENTATION.md](../guides/SECURITY_IMPLEMENTATION.md)

**Implemented Features:**
- Account lockout & suspicious activity detection
- TLS 1.3 enforcement
- API key management
- Input validation framework
- Audit logging
- Secrets scanning

---

**See PROJECT_STANDARDS.md for complete specifications**
