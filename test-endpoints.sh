#!/bin/bash
set -e

VESSEL_URL="${VESSEL_URL:-http://localhost:8181}"
echo "Testing Identity Vessel at $VESSEL_URL"
echo "========================================"

# Generate test API key
echo -e "\n1. Generating test API key..."
export API_KEY_SECRET="test-secret-for-development-min-32-chars-long"
TEST_KEY=$(bun -e "
import { generateApiKey } from './src/services/keyGeneration.ts';
const result = generateApiKey('metabob_com', 'usr_test', { scopes: ['read', 'write', 'admin'] });
console.log(result.key);
")
echo "Generated key: ${TEST_KEY:0:50}..."

# Test health endpoint
echo -e "\n2. Testing /health endpoint..."
curl -s "$VESSEL_URL/health" | python3 -m json.tool
echo "✓ Health check passed"

# Test capabilities endpoint
echo -e "\n3. Testing /capabilities endpoint..."
curl -s "$VESSEL_URL/capabilities" | python3 -m json.tool | head -20
echo "✓ Capabilities check passed"

# Test authentication resolution - valid key
echo -e "\n4. Testing /v1/auth/resolve with VALID key..."
RESULT=$(curl -s "$VESSEL_URL/v1/auth/resolve" -X POST \
  -H 'Content-Type: application/json' \
  -d "{
    \"impulse\": {
      \"type\": \"authentication\",
      \"pointer\": {
        \"type\": \"apiKey\",
        \"apiKey\": \"$TEST_KEY\"
      }
    }
  }" | python3 -m json.tool)

echo "$RESULT"

if echo "$RESULT" | grep -q '"authenticated": true'; then
  echo "✓ Valid key authentication passed"
else
  echo "✗ Valid key authentication FAILED"
  exit 1
fi

# Test authentication resolution - invalid key
echo -e "\n5. Testing /v1/auth/resolve with INVALID key..."
RESULT=$(curl -s "$VESSEL_URL/v1/auth/resolve" -X POST \
  -H 'Content-Type: application/json' \
  -d '{
    "impulse": {
      "type": "authentication",
      "pointer": {
        "type": "apiKey",
        "apiKey": "invalid-key-12345"
      }
    }
  }' | python3 -m json.tool)

echo "$RESULT"

if echo "$RESULT" | grep -q '"authenticated": false'; then
  echo "✓ Invalid key rejection passed"
else
  echo "✗ Invalid key rejection FAILED"
  exit 1
fi

# Test protected endpoint - list keys
echo -e "\n6. Testing /v1/keys (protected endpoint)..."
RESULT=$(curl -s "$VESSEL_URL/v1/keys" \
  -H "Authorization: Bearer $TEST_KEY" | python3 -m json.tool)

echo "$RESULT"

if echo "$RESULT" | grep -q '"success": true'; then
  echo "✓ Protected endpoint access passed"
else
  echo "✗ Protected endpoint access FAILED"
  exit 1
fi

# Test performance
echo -e "\n7. Performance test (10 authentication requests)..."
START=$(date +%s%N)
for i in {1..10}; do
  curl -s "$VESSEL_URL/v1/auth/resolve" -X POST \
    -H 'Content-Type: application/json' \
    -d "{
      \"impulse\": {
        \"type\": \"authentication\",
        \"pointer\": {
          \"type\": \"apiKey\",
          \"apiKey\": \"$TEST_KEY\"
        }
      }
    }" > /dev/null
done
END=$(date +%s%N)
DURATION=$(( (END - START) / 1000000 ))
AVG=$(( DURATION / 10 ))
echo "Total time: ${DURATION}ms"
echo "Average time: ${AVG}ms per request"

if [ $AVG -lt 100 ]; then
  echo "✓ Performance target met (<100ms avg)"
else
  echo "⚠ Performance slower than expected (target: <100ms)"
fi

echo -e "\n========================================"
echo "All tests passed! ✓"
echo "========================================"
