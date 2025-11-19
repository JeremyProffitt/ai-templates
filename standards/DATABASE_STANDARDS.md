# Database Standards - DynamoDB v1.0

**Organization:** Ally Financial SRE/DevSecOps
**Last Updated:** November 19, 2025

## DynamoDB Table Design

See: [../PROJECT_STANDARDS.md](../PROJECT_STANDARDS.md#dynamodb-standards) (lines 569-657)

**Tables:**
- Users Table (partition key: user_id, GSIs: email, username)
- Sessions Table (partition key: session_id, GSI: user_id, TTL: expires_at)
- Permissions Table (composite key: role_name, permission)

## Best Practices

1. **Use GSIs for alternate access patterns**
2. **Enable TTL for automatic expiration**
3. **Use batch operations when possible**
4. **Implement pagination for large result sets**
5. **Log all database operations with duration**

---

**See PROJECT_STANDARDS.md for complete specifications**
