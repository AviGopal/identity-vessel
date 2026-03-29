#!/bin/bash
# Quick API Key Generator
# Use this until dashboard login is implemented

set -e

cd "$(dirname "$0")"

echo "========================================="
echo "  Metabob API Key Generator"
echo "========================================="
echo ""

# Configuration
export API_KEY_SECRET="${API_KEY_SECRET:-test-secret-for-development-min-32-chars-long}"
export PORT="${PORT:-8181}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379}"

# Prompt for details
echo "Enter details for your API key:"
echo ""
read -p "Organization ID (e.g., metabob_com): " ORG_ID
ORG_ID=${ORG_ID:-metabob_com}

read -p "User ID (e.g., usr_avi): " USER_ID
USER_ID=${USER_ID:-usr_avi}

read -p "Key name (e.g., 'My IDE Key'): " KEY_NAME
KEY_NAME=${KEY_NAME:-My API Key}

read -p "Scopes (comma-separated, e.g., read,write): " SCOPES
SCOPES=${SCOPES:-read,write}

read -p "Expires in days (default: 365): " EXPIRES
EXPIRES=${EXPIRES:-365}

echo ""
echo "Generating API key with:"
echo "  Org: $ORG_ID"
echo "  User: $USER_ID"
echo "  Name: $KEY_NAME"
echo "  Scopes: $SCOPES"
echo "  Expires: $EXPIRES days"
echo ""

# Convert scopes to array format for JavaScript
SCOPES_ARRAY=$(echo "$SCOPES" | sed 's/,/", "/g' | sed 's/^/"/' | sed 's/$/"/')

# Generate the key
API_KEY=$(bun -e "
import { generateApiKey } from './src/services/keyGeneration.ts';
const result = generateApiKey('$ORG_ID', '$USER_ID', {
  name: '$KEY_NAME',
  scopes: [$SCOPES_ARRAY],
  expiresInDays: $EXPIRES
});
console.log(result.key);
")

KEY_ID=$(bun -e "
import { generateApiKey } from './src/services/keyGeneration.ts';
const result = generateApiKey('$ORG_ID', '$USER_ID', {
  name: '$KEY_NAME',
  scopes: [$SCOPES_ARRAY],
  expiresInDays: $EXPIRES
});
console.log(result.keyId);
")

EXPIRES_AT=$(bun -e "
import { generateApiKey } from './src/services/keyGeneration.ts';
const result = generateApiKey('$ORG_ID', '$USER_ID', {
  name: '$KEY_NAME',
  scopes: [$SCOPES_ARRAY],
  expiresInDays: $EXPIRES
});
console.log(result.expiresAt || 'Never');
")

echo "========================================="
echo "  ✓ API Key Generated Successfully"
echo "========================================="
echo ""
echo "YOUR API KEY:"
echo "$API_KEY"
echo ""
echo "Key ID: $KEY_ID"
echo "Expires: $EXPIRES_AT"
echo ""
echo "⚠️  IMPORTANT: Save this key now!"
echo "   This is the only time it will be shown."
echo ""
echo "========================================="
echo "  How to Use This Key"
echo "========================================="
echo ""
echo "1. Configure your IDE/CLI:"
echo "   export METABOB_API_KEY=\"$API_KEY\""
echo ""
echo "2. Make API calls:"
echo "   curl https://api.metabob.com/v2/analysis/scan \\"
echo "     -H \"Authorization: Bearer $API_KEY\" \\"
echo "     -H \"Content-Type: application/json\" \\"
echo "     -d '{\"file\":\"src/index.ts\"}'"
echo ""
echo "3. Test the key locally:"
echo "   ./test-api-key.sh \"$API_KEY\""
echo ""
echo "========================================="
echo ""

# Save to file for reference (key ID only, not the actual key!)
cat > /tmp/metabob-api-key-info.txt <<EOF
API Key Generated: $(date)
Organization: $ORG_ID
User: $USER_ID
Key ID: $KEY_ID
Name: $KEY_NAME
Scopes: $SCOPES
Expires: $EXPIRES_AT

⚠️  The actual API key was shown once and is NOT saved in this file.
    If you lost it, you'll need to generate a new one.
EOF

echo "Key metadata saved to: /tmp/metabob-api-key-info.txt"
echo "(Note: The actual key is NOT saved, only metadata)"
echo ""
