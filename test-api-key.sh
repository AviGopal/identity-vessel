#!/bin/bash
# Test an API key

if [ -z "$1" ]; then
  echo "Usage: ./test-api-key.sh <api-key>"
  echo ""
  echo "Example:"
  echo "  ./test-api-key.sh bWJfdGVzdC1tZXRhYm9iX2NvbS11c3JfYXZpLWtleV94..."
  exit 1
fi

API_KEY="$1"

echo "========================================="
echo "  Testing API Key"
echo "========================================="
echo ""
echo "Key: ${API_KEY:0:50}..."
echo ""

# Check if identity-vessel is running
VESSEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8181/health 2>/dev/null || echo "000")

if [ "$VESSEL_STATUS" != "200" ]; then
  echo "⚠️  Identity vessel not running, starting it..."
  cd "$(dirname "$0")"
  export API_KEY_SECRET="test-secret-for-development-min-32-chars-long"
  export PORT=8181
  export REDIS_URL="redis://localhost:6379"
  bun run src/index.ts > /tmp/vessel-test.log 2>&1 &
  VESSEL_PID=$!
  echo "   Started vessel (PID: $VESSEL_PID)"
  sleep 3
fi

# Test the key
echo "Testing authentication..."
RESULT=$(curl -s -X POST http://localhost:8181/v1/auth/resolve \
  -H 'Content-Type: application/json' \
  -d "{
    \"impulse\": {
      \"type\": \"authentication\",
      \"pointer\": {
        \"type\": \"apiKey\",
        \"apiKey\": \"$API_KEY\"
      }
    }
  }")

echo "$RESULT" | python3 -m json.tool

AUTHENTICATED=$(echo "$RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('authenticated', False))" 2>/dev/null)

echo ""
if [ "$AUTHENTICATED" == "True" ]; then
  echo "========================================="
  echo "  ✓ API Key is VALID"
  echo "========================================="

  ORG_ID=$(echo "$RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('orgId', 'N/A'))" 2>/dev/null)
  USER_ID=$(echo "$RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('userId', 'N/A'))" 2>/dev/null)
  KEY_ID=$(echo "$RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('keyId', 'N/A'))" 2>/dev/null)

  echo ""
  echo "Authenticated as:"
  echo "  Organization: $ORG_ID"
  echo "  User: $USER_ID"
  echo "  Key ID: $KEY_ID"
  echo ""
  echo "This key can now be used to make API calls!"
else
  echo "========================================="
  echo "  ✗ API Key is INVALID"
  echo "========================================="
  echo ""
  REASON=$(echo "$RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('reason', 'Unknown error'))" 2>/dev/null)
  echo "Reason: $REASON"
  echo ""
  echo "Possible issues:"
  echo "1. Key was generated with different secret"
  echo "2. Key was tampered with"
  echo "3. Key has been revoked"
  echo "4. Key format is invalid"
fi

echo ""
