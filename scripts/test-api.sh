#!/bin/bash
#
# test-api.sh
# Test deployed API endpoints
#
# Usage: ./test-api.sh <api-url>
# Example: ./test-api.sh https://abc123.execute-api.us-east-1.amazonaws.com/Prod

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_test() { echo -e "${BLUE}TEST:${NC} $1"; }
print_pass() { echo -e "${GREEN}PASS${NC} $1"; }
print_fail() { echo -e "${RED}FAIL${NC} $1"; exit 1; }

if [ $# -eq 0 ]; then
    echo "Usage: $0 <api-url>"
    echo "Example: $0 https://abc123.execute-api.us-east-1.amazonaws.com/Prod"
    exit 1
fi

API_URL=$1
COOKIE_JAR=$(mktemp)

echo "Testing API: $API_URL"
echo "Cookie jar: $COOKIE_JAR"
echo ""

# Test 1: Health Check
print_test "Health check"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/health")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
    print_pass "Health check returned 200"
else
    print_fail "Health check failed with status $HTTP_CODE"
fi

# Test 2: Register User
print_test "User registration"
TIMESTAMP=$(date +%s)
TEST_EMAIL="test-$TIMESTAMP@example.com"
TEST_PASSWORD="SecureTestPass123!"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$TEST_EMAIL\",
        \"username\": \"testuser$TIMESTAMP\",
        \"password\": \"$TEST_PASSWORD\",
        \"name\": \"Test User\"
    }")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "201" ]; then
    print_pass "User registration successful"
    USER_ID=$(echo "$BODY" | grep -o '"user_id":"[^"]*"' | cut -d'"' -f4)
    echo "  User ID: $USER_ID"
else
    print_fail "User registration failed with status $HTTP_CODE: $BODY"
fi

# Test 3: Login
print_test "User login"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -c "$COOKIE_JAR" \
    -d "{
        \"email\": \"$TEST_EMAIL\",
        \"password\": \"$TEST_PASSWORD\"
    }")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

if [ "$HTTP_CODE" = "200" ]; then
    print_pass "User login successful"
    echo "  Session cookie saved"
else
    print_fail "User login failed with status $HTTP_CODE"
fi

# Test 4: Get Profile (Authenticated)
print_test "Get user profile (authenticated)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/api/v1/profile" \
    -b "$COOKIE_JAR")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

if [ "$HTTP_CODE" = "200" ]; then
    print_pass "Profile retrieval successful"
else
    print_fail "Profile retrieval failed with status $HTTP_CODE"
fi

# Test 5: Unauthorized Access
print_test "Unauthorized access (no cookie)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/api/v1/profile")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

if [ "$HTTP_CODE" = "401" ]; then
    print_pass "Unauthorized access correctly rejected"
else
    print_fail "Expected 401, got $HTTP_CODE"
fi

# Test 6: Logout
print_test "User logout"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/auth/logout" \
    -b "$COOKIE_JAR")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

if [ "$HTTP_CODE" = "200" ]; then
    print_pass "User logout successful"
else
    print_fail "User logout failed with status $HTTP_CODE"
fi

# Cleanup
rm -f "$COOKIE_JAR"

echo ""
echo -e "${GREEN}All tests passed!${NC}"
echo "Test user email: $TEST_EMAIL"
echo ""
