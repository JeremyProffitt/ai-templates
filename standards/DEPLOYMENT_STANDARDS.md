# Deployment Standards - AWS SAM & GitHub Actions v1.0

**Organization:** Ally Financial SRE/DevSecOps
**Last Updated:** November 19, 2025

## Deployment Overview

See: [../PROJECT_STANDARDS.md](../PROJECT_STANDARDS.md#deployment-standards) (lines 660-1009)

**Deployment Stack:**
- AWS SAM for infrastructure as code
- GitHub Actions for CI/CD
- Makefile for build automation
- Multi-environment support (dev, staging, prod)

## SAM Template

Complete SAM template with:
- Lambda function configuration
- API Gateway setup
- DynamoDB tables
- IAM roles with least-privilege
- CloudWatch Logs

## GitHub Actions Workflow

Automated pipeline:
- Run tests
- Security scanning
- Build Lambda binary
- Deploy to AWS
- Get API endpoint

---

**See PROJECT_STANDARDS.md for complete specifications**
